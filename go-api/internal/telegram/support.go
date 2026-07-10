package telegram

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrSupportUnavailable = errors.New("telegram support service unavailable")

type SupportMessage struct {
	ID             int64  `json:"id"`
	Role           string `json:"from"`
	Message        string `json:"text"`
	MessageType    string `json:"type"`
	FileName       string `json:"fileName,omitempty"`
	MimeType       string `json:"mimeType,omitempty"`
	TelegramFileID string `json:"fileId,omitempty"`
	CreatedAt      int64  `json:"time"`
}

type SupportAttachment struct {
	Type     string
	FileName string
	MimeType string
	Caption  string
	Data     []byte
}

type SupportFile struct {
	FileName string `json:"fileName"`
	MimeType string `json:"mimeType"`
	Data     string `json:"data"`
}

type supportConversation struct {
	ID              int64
	UserID          int64
	Email           string
	ChatID          int64
	MessageThreadID int64
	Status          string
	PurgeAfter      int64
}

type telegramAPIResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Result      struct {
		MessageID       int64 `json:"message_id"`
		MessageThreadID int64 `json:"message_thread_id"`
		Photo           []struct {
			FileID string `json:"file_id"`
		} `json:"photo"`
		Document *struct {
			FileID string `json:"file_id"`
		} `json:"document"`
		Voice *struct {
			FileID string `json:"file_id"`
		} `json:"voice"`
	} `json:"result"`
}

type telegramGetFileResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Result      struct {
		FileID   string `json:"file_id"`
		FilePath string `json:"file_path"`
	} `json:"result"`
}

func (s *Service) SendSupportMessage(ctx context.Context, userID int64, email, message string) (bool, error) {
	if s == nil || s.db == nil {
		return false, ErrSupportUnavailable
	}
	email = strings.TrimSpace(email)
	message = strings.TrimSpace(message)
	if userID <= 0 || message == "" {
		return false, errors.New("invalid support message")
	}
	if err := s.ensureSupportSchema(ctx); err != nil {
		return false, err
	}

	conversation, err := s.supportConversationForUser(ctx, userID, email)
	if err != nil {
		return false, err
	}

	response, err := s.sendSupportTelegramMessage(ctx, conversation.ChatID, conversation.MessageThreadID, formatSupportUserMessage(email, message))
	if err != nil && isStaleSupportTopicError(err) {
		_ = s.deleteSupportConversationHistory(ctx, conversation.ID, time.Now().Unix())
		conversation, err = s.recreateSupportTopic(ctx, conversation, email)
		if err == nil {
			response, err = s.sendSupportTelegramMessage(ctx, conversation.ChatID, conversation.MessageThreadID, formatSupportUserMessage(email, message))
		}
	}
	if err != nil {
		return false, err
	}

	var telegramMessageID *int64
	if response.Result.MessageID > 0 {
		next := response.Result.MessageID
		telegramMessageID = &next
	}
	if err := s.appendSupportTextMessage(ctx, conversation.ID, userID, "user", message, telegramMessageID); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) SendSupportAttachment(ctx context.Context, userID int64, email string, attachment SupportAttachment) (bool, error) {
	if s == nil || s.db == nil {
		return false, ErrSupportUnavailable
	}
	email = strings.TrimSpace(email)
	attachment.Type = normalizeSupportMessageType(attachment.Type)
	attachment.FileName = strings.TrimSpace(attachment.FileName)
	attachment.MimeType = strings.TrimSpace(attachment.MimeType)
	attachment.Caption = strings.TrimSpace(attachment.Caption)
	if userID <= 0 || len(attachment.Data) == 0 {
		return false, errors.New("invalid support attachment")
	}
	if attachment.FileName == "" {
		attachment.FileName = "attachment"
	}
	if err := s.ensureSupportSchema(ctx); err != nil {
		return false, err
	}

	conversation, err := s.supportConversationForUser(ctx, userID, email)
	if err != nil {
		return false, err
	}

	caption := attachment.Caption
	if caption == "" {
		caption = supportAttachmentLabel(attachment.Type, attachment.FileName)
	}
	response, err := s.sendSupportTelegramAttachment(ctx, conversation.ChatID, conversation.MessageThreadID, email, attachment, "")
	if err != nil && isStaleSupportTopicError(err) {
		_ = s.deleteSupportConversationHistory(ctx, conversation.ID, time.Now().Unix())
		conversation, err = s.recreateSupportTopic(ctx, conversation, email)
		if err == nil {
			response, err = s.sendSupportTelegramAttachment(ctx, conversation.ChatID, conversation.MessageThreadID, email, attachment, "")
		}
	}
	if err != nil {
		return false, err
	}

	var telegramMessageID *int64
	if response.Result.MessageID > 0 {
		next := response.Result.MessageID
		telegramMessageID = &next
	}
	if err := s.appendSupportAttachmentMessage(ctx, conversation.ID, userID, "user", caption, attachment, response.supportFileID(), telegramMessageID); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) SupportMessages(ctx context.Context, userID int64) ([]SupportMessage, error) {
	if s == nil || s.db == nil {
		return nil, ErrSupportUnavailable
	}
	if userID <= 0 {
		return nil, errors.New("invalid user")
	}
	if err := s.ensureSupportSchema(ctx); err != nil {
		return nil, err
	}

	chatID := s.supportChatID()
	if chatID == 0 {
		return nil, ErrSupportUnavailable
	}

	conversation, err := s.supportConversationByUser(ctx, userID, chatID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []SupportMessage{}, nil
		}
		return nil, err
	}
	if conversation.Status == "purged" || conversation.Status == "closed" {
		return []SupportMessage{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.id, m.direction, m.message, m.message_type, m.file_name, m.mime_type, m.telegram_file_id, m.created_at
FROM v2_support_message m
JOIN v2_support_conversation c ON c.id = m.conversation_id
WHERE c.user_id = $1 AND c.chat_id = $2
ORDER BY m.id ASC`, userID, chatID)
	if err != nil {
		return nil, fmt.Errorf("query support messages: %w", err)
	}
	defer rows.Close()

	result := make([]SupportMessage, 0)
	for rows.Next() {
		var item SupportMessage
		if err := rows.Scan(&item.ID, &item.Role, &item.Message, &item.MessageType, &item.FileName, &item.MimeType, &item.TelegramFileID, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan support message: %w", err)
		}
		item.MessageType = normalizeSupportMessageType(item.MessageType)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate support messages: %w", err)
	}
	return result, nil
}

func (s *Service) SupportFile(ctx context.Context, userID, messageID int64) (SupportFile, error) {
	if s == nil || s.db == nil {
		return SupportFile{}, ErrSupportUnavailable
	}
	if userID <= 0 || messageID <= 0 {
		return SupportFile{}, errors.New("invalid support file")
	}
	if err := s.ensureSupportSchema(ctx); err != nil {
		return SupportFile{}, err
	}

	chatID := s.supportChatID()
	if chatID == 0 {
		return SupportFile{}, ErrSupportUnavailable
	}

	var file SupportFile
	var telegramFileID string
	var messageType string
	err := s.db.QueryRowContext(ctx, `SELECT m.file_name, m.mime_type, m.telegram_file_id, m.message_type
FROM v2_support_message m
JOIN v2_support_conversation c ON c.id = m.conversation_id
WHERE m.id = $1 AND c.user_id = $2 AND c.chat_id = $3
LIMIT 1`, messageID, userID, chatID).Scan(&file.FileName, &file.MimeType, &telegramFileID, &messageType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SupportFile{}, errors.New("support file not found")
		}
		return SupportFile{}, fmt.Errorf("query support file: %w", err)
	}
	if normalizeSupportMessageType(messageType) == "text" || strings.TrimSpace(telegramFileID) == "" {
		return SupportFile{}, errors.New("support file not found")
	}

	data, err := s.downloadTelegramSupportFile(ctx, telegramFileID)
	if err != nil {
		return SupportFile{}, err
	}
	file.Data = base64.StdEncoding.EncodeToString(data)
	return file, nil
}

func (s *Service) handleSupportWebhookMessage(ctx context.Context, payload map[string]any) (bool, error) {
	if s == nil || s.db == nil {
		return false, nil
	}
	chatPayload, ok := payload["chat"].(map[string]any)
	if !ok {
		return false, nil
	}
	chatID, ok := anyToInt64(chatPayload["id"])
	if !ok || chatID == 0 || chatID != s.supportChatID() {
		return false, nil
	}
	threadID, ok := anyToInt64(payload["message_thread_id"])
	if !ok || threadID <= 0 {
		return false, nil
	}
	if err := s.ensureSupportSchema(ctx); err != nil {
		return true, err
	}

	conversation, err := s.supportConversationByThread(ctx, chatID, threadID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return true, err
	}

	if isSupportTopicClosedOrDeletedPayload(payload) {
		log.Printf("support topic closed/deleted chat_id=%d thread_id=%d conversation_id=%d", chatID, threadID, conversation.ID)
		return true, s.deleteSupportConversationHistory(ctx, conversation.ID, time.Now().Unix())
	}

	if fromPayload, ok := payload["from"].(map[string]any); ok {
		fromID, _ := anyToInt64(fromPayload["id"])
		if strings.EqualFold(strings.TrimSpace(anyToString(fromPayload["is_bot"])), "true") && fromID == s.supportBotID() {
			return true, nil
		}
	}

	text := strings.TrimSpace(anyToString(payload["text"]))
	if text == "" {
		return true, nil
	}

	var telegramMessageID *int64
	if messageID, ok := anyToInt64(payload["message_id"]); ok && messageID > 0 {
		telegramMessageID = &messageID
	}
	return true, s.appendSupportTextMessage(ctx, conversation.ID, conversation.UserID, "agent", text, telegramMessageID)
}

func (s *Service) supportConversationForUser(ctx context.Context, userID int64, email string) (supportConversation, error) {
	chatID := s.supportChatID()
	if chatID == 0 || strings.TrimSpace(s.supportBotToken()) == "" {
		return supportConversation{}, ErrSupportUnavailable
	}

	conversation, err := s.supportConversationByUser(ctx, userID, chatID)
	if err == nil {
		if email != "" && email != conversation.Email {
			_, _ = s.db.ExecContext(ctx, `UPDATE v2_support_conversation SET email = $2, updated_at = $3 WHERE id = $1`, conversation.ID, email, time.Now().Unix())
			conversation.Email = email
		}
		if conversation.Status == "purged" || conversation.Status == "closed" {
			return s.recreateSupportTopic(ctx, conversation, email)
		}
		return conversation, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return supportConversation{}, err
	}

	return s.createSupportConversation(ctx, userID, email, chatID)
}

func (s *Service) supportConversationByUser(ctx context.Context, userID, chatID int64) (supportConversation, error) {
	var conversation supportConversation
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, email, chat_id, message_thread_id, status, purge_after
FROM v2_support_conversation
WHERE user_id = $1 AND chat_id = $2
LIMIT 1`, userID, chatID).Scan(&conversation.ID, &conversation.UserID, &conversation.Email, &conversation.ChatID, &conversation.MessageThreadID, &conversation.Status, &conversation.PurgeAfter)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return supportConversation{}, err
		}
		return supportConversation{}, fmt.Errorf("query support conversation: %w", err)
	}
	return conversation, nil
}

func (s *Service) createSupportConversation(ctx context.Context, userID int64, email string, chatID int64) (supportConversation, error) {
	var conversation supportConversation
	now := time.Now().Unix()
	topicName := supportTopicName(userID, email)
	topic, err := s.createSupportForumTopic(ctx, chatID, topicName)
	if err != nil {
		return supportConversation{}, err
	}
	if topic.Result.MessageThreadID <= 0 {
		return supportConversation{}, errors.New("telegram did not return message_thread_id")
	}

	err = s.db.QueryRowContext(ctx, `INSERT INTO v2_support_conversation (user_id, email, chat_id, message_thread_id, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'active', $5, $5)
RETURNING id`, userID, email, chatID, topic.Result.MessageThreadID, now).Scan(&conversation.ID)
	if err != nil {
		return supportConversation{}, fmt.Errorf("create support conversation: %w", err)
	}
	conversation.UserID = userID
	conversation.Email = email
	conversation.ChatID = chatID
	conversation.MessageThreadID = topic.Result.MessageThreadID
	return conversation, nil
}

func (s *Service) supportConversationByThread(ctx context.Context, chatID, threadID int64) (supportConversation, error) {
	var conversation supportConversation
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, email, chat_id, message_thread_id, purge_after
FROM v2_support_conversation
WHERE chat_id = $1 AND message_thread_id = $2
LIMIT 1`, chatID, threadID).Scan(&conversation.ID, &conversation.UserID, &conversation.Email, &conversation.ChatID, &conversation.MessageThreadID, &conversation.PurgeAfter)
	return conversation, err
}

func (s *Service) recreateSupportTopic(ctx context.Context, conversation supportConversation, email string) (supportConversation, error) {
	topic, err := s.createSupportForumTopic(ctx, conversation.ChatID, supportTopicName(conversation.UserID, firstNonEmpty(email, conversation.Email)))
	if err != nil {
		return supportConversation{}, err
	}
	if topic.Result.MessageThreadID <= 0 {
		return supportConversation{}, errors.New("telegram did not return message_thread_id")
	}
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `UPDATE v2_support_conversation
SET message_thread_id = $2, status = 'active', updated_at = $3
WHERE id = $1`, conversation.ID, topic.Result.MessageThreadID, now); err != nil {
		return supportConversation{}, fmt.Errorf("update support topic: %w", err)
	}
	conversation.MessageThreadID = topic.Result.MessageThreadID
	return conversation, nil
}

func (s *Service) deleteSupportConversationHistory(ctx context.Context, conversationID, beforeOrAt int64) error {
	if conversationID <= 0 {
		return nil
	}
	now := time.Now().Unix()
	if beforeOrAt <= 0 {
		beforeOrAt = now
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM v2_support_message
WHERE conversation_id = $1 AND created_at <= $2`, conversationID, beforeOrAt); err != nil {
		return fmt.Errorf("delete support messages: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE v2_support_conversation
SET purge_after = 0, purge_before = 0, status = 'purged', updated_at = $2
WHERE id = $1`, conversationID, now); err != nil {
		return fmt.Errorf("mark support conversation purged: %w", err)
	}
	return nil
}

func isSupportTopicClosedOrDeletedPayload(payload map[string]any) bool {
	for _, key := range []string{
		"forum_topic_closed",
		"forum_topic_deleted",
		"general_forum_topic_hidden",
	} {
		if _, ok := payload[key]; ok {
			return true
		}
	}
	return false
}

func (s *Service) appendSupportTextMessage(ctx context.Context, conversationID, userID int64, direction, message string, telegramMessageID *int64) error {
	return s.appendSupportMessage(ctx, conversationID, userID, direction, message, "text", "", "", "", telegramMessageID)
}

func (s *Service) appendSupportAttachmentMessage(ctx context.Context, conversationID, userID int64, direction, message string, attachment SupportAttachment, telegramFileID string, telegramMessageID *int64) error {
	return s.appendSupportMessage(ctx, conversationID, userID, direction, message, attachment.Type, attachment.FileName, attachment.MimeType, telegramFileID, telegramMessageID)
}

func (s *Service) appendSupportMessage(ctx context.Context, conversationID, userID int64, direction, message, messageType, fileName, mimeType, telegramFileID string, telegramMessageID *int64) error {
	now := time.Now().Unix()
	messageType = normalizeSupportMessageType(messageType)
	fileName = strings.TrimSpace(fileName)
	mimeType = strings.TrimSpace(mimeType)
	telegramFileID = strings.TrimSpace(telegramFileID)
	if telegramMessageID != nil {
		_, err := s.db.ExecContext(ctx, `INSERT INTO v2_support_message (conversation_id, user_id, direction, message, message_type, file_name, mime_type, telegram_file_id, telegram_message_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
ON CONFLICT (conversation_id, telegram_message_id) DO UPDATE SET
	message = EXCLUDED.message,
	message_type = EXCLUDED.message_type,
	file_name = EXCLUDED.file_name,
	mime_type = EXCLUDED.mime_type,
	telegram_file_id = EXCLUDED.telegram_file_id,
	updated_at = EXCLUDED.updated_at`, conversationID, userID, direction, message, messageType, fileName, mimeType, telegramFileID, *telegramMessageID, now)
		if err != nil {
			return fmt.Errorf("insert support message: %w", err)
		}
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO v2_support_message (conversation_id, user_id, direction, message, message_type, file_name, mime_type, telegram_file_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)`, conversationID, userID, direction, message, messageType, fileName, mimeType, telegramFileID, now); err != nil {
		return fmt.Errorf("insert support message: %w", err)
	}
	return nil
}

func (response telegramAPIResponse) supportFileID() string {
	switch {
	case response.Result.Voice != nil && strings.TrimSpace(response.Result.Voice.FileID) != "":
		return strings.TrimSpace(response.Result.Voice.FileID)
	case response.Result.Document != nil && strings.TrimSpace(response.Result.Document.FileID) != "":
		return strings.TrimSpace(response.Result.Document.FileID)
	case len(response.Result.Photo) > 0:
		return strings.TrimSpace(response.Result.Photo[len(response.Result.Photo)-1].FileID)
	default:
		return ""
	}
}

func (s *Service) createSupportForumTopic(ctx context.Context, chatID int64, name string) (telegramAPIResponse, error) {
	values := url.Values{}
	values.Set("chat_id", strconv.FormatInt(chatID, 10))
	values.Set("name", name)
	return s.postSupportForm(ctx, "createForumTopic", values)
}

func (s *Service) sendSupportTelegramMessage(ctx context.Context, chatID, threadID int64, text string) (telegramAPIResponse, error) {
	values := url.Values{}
	values.Set("chat_id", strconv.FormatInt(chatID, 10))
	values.Set("message_thread_id", strconv.FormatInt(threadID, 10))
	values.Set("text", text)
	return s.postSupportForm(ctx, "sendMessage", values)
}

func (s *Service) checkSupportTopic(ctx context.Context, chatID, threadID int64) error {
	values := url.Values{}
	values.Set("chat_id", strconv.FormatInt(chatID, 10))
	values.Set("message_thread_id", strconv.FormatInt(threadID, 10))
	values.Set("action", "typing")
	_, err := s.postSupportForm(ctx, "sendChatAction", values)
	return err
}

func (s *Service) sendSupportTelegramAttachment(ctx context.Context, chatID, threadID int64, email string, attachment SupportAttachment, caption string) (telegramAPIResponse, error) {
	method := "sendDocument"
	field := "document"
	switch attachment.Type {
	case "image":
		method = "sendPhoto"
		field = "photo"
	case "voice":
		method = "sendVoice"
		field = "voice"
	}

	values := map[string]string{
		"chat_id":           strconv.FormatInt(chatID, 10),
		"message_thread_id": strconv.FormatInt(threadID, 10),
		"caption":           formatSupportAttachmentCaption(email, caption),
	}
	response, err := s.postSupportMultipart(ctx, method, values, field, attachment.FileName, attachment.MimeType, attachment.Data)
	if err != nil && attachment.Type == "voice" {
		values["caption"] = formatSupportUserMessage(email, caption+"（语音文件）")
		return s.postSupportMultipart(ctx, "sendDocument", values, "document", attachment.FileName, attachment.MimeType, attachment.Data)
	}
	return response, err
}

func (s *Service) postSupportForm(ctx context.Context, method string, values url.Values) (telegramAPIResponse, error) {
	var payload telegramAPIResponse
	token := strings.TrimSpace(s.supportBotToken())
	if token == "" {
		return payload, ErrSupportUnavailable
	}
	endpoint := "https://api.telegram.org/bot" + token + "/" + strings.TrimSpace(method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return payload, fmt.Errorf("build telegram support request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return payload, fmt.Errorf("send telegram support request: %w", err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode telegram support response: %w", err)
	}
	if !payload.OK {
		message := strings.TrimSpace(payload.Description)
		if message == "" {
			message = "telegram support request failed"
		}
		return payload, errors.New(message)
	}
	return payload, nil
}

func (s *Service) postSupportMultipart(ctx context.Context, method string, values map[string]string, fieldName, fileName, mimeType string, data []byte) (telegramAPIResponse, error) {
	var payload telegramAPIResponse
	token := strings.TrimSpace(s.supportBotToken())
	if token == "" {
		return payload, ErrSupportUnavailable
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range values {
		if err := writer.WriteField(key, value); err != nil {
			return payload, fmt.Errorf("build telegram multipart field: %w", err)
		}
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fieldName, strings.ReplaceAll(fileName, `"`, "")))
	header.Set("Content-Type", mimeType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return payload, fmt.Errorf("build telegram multipart file: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return payload, fmt.Errorf("write telegram multipart file: %w", err)
	}
	if err := writer.Close(); err != nil {
		return payload, fmt.Errorf("close telegram multipart: %w", err)
	}

	endpoint := "https://api.telegram.org/bot" + token + "/" + strings.TrimSpace(method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return payload, fmt.Errorf("build telegram support request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := s.client.Do(req)
	if err != nil {
		return payload, fmt.Errorf("send telegram support request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return payload, fmt.Errorf("read telegram support response: %w", err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, fmt.Errorf("decode telegram support response: %w", err)
	}
	if !payload.OK {
		message := strings.TrimSpace(payload.Description)
		if message == "" {
			message = strings.TrimSpace(string(raw))
		}
		if message == "" {
			message = "telegram support request failed"
		}
		return payload, errors.New(message)
	}
	return payload, nil
}

func (s *Service) downloadTelegramSupportFile(ctx context.Context, fileID string) ([]byte, error) {
	token := strings.TrimSpace(s.supportBotToken())
	fileID = strings.TrimSpace(fileID)
	if token == "" || fileID == "" {
		return nil, ErrSupportUnavailable
	}

	values := url.Values{}
	values.Set("file_id", fileID)
	endpoint := "https://api.telegram.org/bot" + token + "/getFile"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build telegram getFile request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send telegram getFile request: %w", err)
	}
	defer resp.Body.Close()

	var payload telegramGetFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode telegram getFile response: %w", err)
	}
	if !payload.OK || strings.TrimSpace(payload.Result.FilePath) == "" {
		message := strings.TrimSpace(payload.Description)
		if message == "" {
			message = "telegram getFile failed"
		}
		return nil, errors.New(message)
	}

	fileURL := "https://api.telegram.org/file/bot" + token + "/" + strings.TrimLeft(payload.Result.FilePath, "/")
	fileReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build telegram file download request: %w", err)
	}
	fileResp, err := s.client.Do(fileReq)
	if err != nil {
		return nil, fmt.Errorf("download telegram file: %w", err)
	}
	defer fileResp.Body.Close()
	if fileResp.StatusCode < 200 || fileResp.StatusCode >= 300 {
		return nil, fmt.Errorf("download telegram file status %d", fileResp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(fileResp.Body, 10*1024*1024+1))
	if err != nil {
		return nil, fmt.Errorf("read telegram file: %w", err)
	}
	if len(data) == 0 || len(data) > 10*1024*1024 {
		return nil, errors.New("telegram file size invalid")
	}
	return data, nil
}

func (s *Service) ensureSupportSchema(ctx context.Context) error {
	s.supportSchemaOnce.Do(func() {
		for _, stmt := range []string{
			`CREATE TABLE IF NOT EXISTS v2_support_conversation (
id INTEGER GENERATED BY DEFAULT AS IDENTITY NOT NULL,
user_id INTEGER NOT NULL,
email varchar(128) NOT NULL DEFAULT '',
chat_id BIGINT NOT NULL,
message_thread_id BIGINT NOT NULL,
status varchar(16) NOT NULL DEFAULT 'active',
purge_after INTEGER NOT NULL DEFAULT 0,
purge_before INTEGER NOT NULL DEFAULT 0,
created_at INTEGER NOT NULL,
updated_at INTEGER NOT NULL,
PRIMARY KEY (id),
CONSTRAINT uniq_v2_support_conversation_user_chat UNIQUE (user_id, chat_id),
CONSTRAINT uniq_v2_support_conversation_thread UNIQUE (chat_id, message_thread_id)
)`,
			`CREATE TABLE IF NOT EXISTS v2_support_message (
id INTEGER GENERATED BY DEFAULT AS IDENTITY NOT NULL,
conversation_id INTEGER NOT NULL,
user_id INTEGER NOT NULL,
direction varchar(16) NOT NULL,
message text NOT NULL,
message_type varchar(16) NOT NULL DEFAULT 'text',
file_name text NOT NULL DEFAULT '',
mime_type varchar(128) NOT NULL DEFAULT '',
telegram_file_id text NOT NULL DEFAULT '',
telegram_message_id BIGINT DEFAULT NULL,
created_at INTEGER NOT NULL,
updated_at INTEGER NOT NULL,
PRIMARY KEY (id),
CONSTRAINT uniq_v2_support_message_telegram UNIQUE (conversation_id, telegram_message_id)
)`,
			`CREATE INDEX IF NOT EXISTS idx_v2_support_message_conversation ON v2_support_message(conversation_id, id)`,
		} {
			if _, err := s.db.ExecContext(ctx, stmt); err != nil {
				s.supportSchemaErr = fmt.Errorf("ensure support schema: %w", err)
				return
			}
		}
		for _, stmt := range []string{
			`ALTER TABLE v2_support_conversation ADD COLUMN IF NOT EXISTS purge_after INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE v2_support_conversation ADD COLUMN IF NOT EXISTS purge_before INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE v2_support_message ADD COLUMN IF NOT EXISTS message_type varchar(16) NOT NULL DEFAULT 'text'`,
			`ALTER TABLE v2_support_message ADD COLUMN IF NOT EXISTS file_name text NOT NULL DEFAULT ''`,
			`ALTER TABLE v2_support_message ADD COLUMN IF NOT EXISTS mime_type varchar(128) NOT NULL DEFAULT ''`,
			`ALTER TABLE v2_support_message ADD COLUMN IF NOT EXISTS telegram_file_id text NOT NULL DEFAULT ''`,
		} {
			if _, err := s.db.ExecContext(ctx, stmt); err != nil {
				s.supportSchemaErr = fmt.Errorf("ensure support message media schema: %w", err)
				return
			}
		}
	})
	return s.supportSchemaErr
}

func (s *Service) supportBotToken() string {
	cfg := s.currentConfig()
	if token := strings.TrimSpace(cfg.TelegramSupportBotToken); token != "" {
		return token
	}
	return strings.TrimSpace(cfg.TelegramBotToken)
}

func (s *Service) supportBotID() int64 {
	token := s.supportBotToken()
	id, _, ok := strings.Cut(token, ":")
	if !ok {
		return 0
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func (s *Service) supportChatID() int64 {
	return s.currentConfig().TelegramSupportChatID
}

func supportTopicName(userID int64, email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		email = "user-" + strconv.FormatInt(userID, 10)
	}
	name := email + " #" + strconv.FormatInt(userID, 10)
	if len([]rune(name)) <= 128 {
		return name
	}
	runes := []rune(name)
	return string(runes[:128])
}

func formatSupportUserMessage(email, message string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		email = "unknown"
	}
	return fmt.Sprintf("用户：%s\n\n%s", email, strings.TrimSpace(message))
}

func formatSupportAttachmentCaption(email, caption string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		email = "unknown"
	}
	caption = strings.TrimSpace(caption)
	if caption == "" {
		return fmt.Sprintf("用户：%s", email)
	}
	return fmt.Sprintf("用户：%s\n\n%s", email, caption)
}

func DecodeSupportAttachment(kind, fileName, mimeType, dataBase64, caption string) (SupportAttachment, error) {
	kind = normalizeSupportMessageType(kind)
	if kind == "text" {
		return SupportAttachment{}, errors.New("invalid attachment type")
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dataBase64))
	if err != nil {
		return SupportAttachment{}, errors.New("invalid attachment data")
	}
	if len(data) <= 0 || len(data) > 10*1024*1024 {
		return SupportAttachment{}, errors.New("attachment size must be between 1 byte and 10 MB")
	}
	return SupportAttachment{
		Type:     kind,
		FileName: strings.TrimSpace(fileName),
		MimeType: strings.TrimSpace(mimeType),
		Caption:  strings.TrimSpace(caption),
		Data:     data,
	}, nil
}

func normalizeSupportMessageType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "image", "photo":
		return "image"
	case "voice", "audio":
		return "voice"
	case "file", "document":
		return "file"
	default:
		return "text"
	}
}

func supportAttachmentLabel(messageType, fileName string) string {
	fileName = strings.TrimSpace(fileName)
	switch normalizeSupportMessageType(messageType) {
	case "image":
		if fileName != "" {
			return "[图片] " + fileName
		}
		return "[图片]"
	case "voice":
		if fileName != "" {
			return "[语音] " + fileName
		}
		return "[语音]"
	case "file":
		if fileName != "" {
			return "[附件] " + fileName
		}
		return "[附件]"
	default:
		return strings.TrimSpace(fileName)
	}
}

func isStaleSupportTopicError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	for _, token := range []string{"message thread not found", "thread not found", "topic closed", "topic_deleted", "message thread is closed"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
