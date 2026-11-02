package telegram

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (s *Service) answerAICallback(ctx context.Context, id, text string, alert bool) error {
	cfg := s.currentConfig()
	vals := url.Values{"callback_query_id": {id}, "text": {text}}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+cfg.TelegramBotToken+"/answerCallbackQuery", strings.NewReader(vals.Encode()))
	if err != nil {
		return errors.New("Telegram callback unavailable")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return errors.New("Telegram callback unavailable")
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 65536))
	return nil
}
