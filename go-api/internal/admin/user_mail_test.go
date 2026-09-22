package admin

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const bulkMailExclusionQuery = `SELECT match_user_ids, match_user_id_ranges FROM v2_insider_rule ORDER BY id ASC`

func newBulkMailTestService(t *testing.T) (*DBService, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	})
	service := &DBService{db: db}
	service.nodeAddressEnsureOnce.Do(func() {})
	service.mailSender = func(host string, port int, encryption, username, password, from, fromName, to, subject, body string) error {
		t.Fatalf("unexpected SMTP attempt to %s", to)
		return nil
	}
	return service, mock
}

func expectMailExclusions(mock sqlmock.Sqlmock, ids, ranges string) {
	rows := sqlmock.NewRows([]string{"match_user_ids", "match_user_id_ranges"})
	if ids != "" || ranges != "" {
		rows.AddRow(ids, ranges)
	}
	mock.ExpectQuery("^" + regexp.QuoteMeta(bulkMailExclusionQuery) + "$").WillReturnRows(rows)
}

func expectMailRecipient(mock sqlmock.Sqlmock, userID int64, email string) {
	mock.ExpectQuery("^" + regexp.QuoteMeta(`SELECT email FROM v2_user WHERE id = $1`) + "$").WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow(email))
}

func expectAllowedMail(mock sqlmock.Sqlmock, userID int64, email string, sendErr error) {
	expectMailRecipient(mock, userID, email)
	expectMailExclusions(mock, "", "")
	var errorText any
	if sendErr != nil {
		errorText = sendErr.Error()
	}
	mock.ExpectExec(`INSERT INTO v2_mail_log`).WithArgs(email, "Notice", "notify", errorText, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
}

func TestBulkMailPreviewAndSelection(t *testing.T) {
	for _, previewOnly := range []bool{true, false} {
		service, mock := newBulkMailTestService(t)
		expectMailExclusions(mock, `["2","3"]`, `["3-5"]`)
		mock.ExpectQuery("^" + regexp.QuoteMeta(`SELECT u.id, u.email FROM v2_user u WHERE u.banned = $1 ORDER BY u.id DESC`) + "$").WithArgs(int64(0)).
			WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).AddRow(8, " ").AddRow(6, " a@example.com ").AddRow(5, "b@example.com").AddRow(3, "c@example.com").AddRow(2, "d@example.com").AddRow(1, "e@example.com"))
		req := UserMailRequest{Sort: "id", Filters: []UserFilter{{Key: "banned", Condition: "=", Value: "0"}}}
		var preview UserMailPreview
		var err error
		if previewOnly {
			preview, err = service.PreviewUserMail(context.Background(), req)
		} else {
			var recipients []bulkMailRecipient
			recipients, preview, err = service.selectBulkMailRecipients(context.Background(), req)
			if !reflect.DeepEqual(recipients, []bulkMailRecipient{{6, "a@example.com"}, {1, "e@example.com"}}) {
				t.Fatalf("unexpected recipients: %#v", recipients)
			}
		}
		if err != nil || preview != (UserMailPreview{Total: 6, Excluded: 3, Unavailable: 1, Eligible: 2}) {
			t.Fatalf("unexpected preview: %#v, %v", preview, err)
		}
	}
}

func TestBulkMailRejectsUnreadableExclusions(t *testing.T) {
	for _, rule := range [][2]string{{`broken`, `[]`}, {`null`, `["1-2"]`}, {`[]`, `[]`}, {`[1]`, `[]`}, {`["1",""]`, `[]`}, {`[]`, `["0-5"]`}} {
		t.Run(rule[0]+rule[1], func(t *testing.T) {
			service, mock := newBulkMailTestService(t)
			expectMailExclusions(mock, rule[0], rule[1])
			if _, err := service.PreviewUserMail(context.Background(), UserMailRequest{}); err == nil {
				t.Fatal("invalid rule must prevent recipient query")
			}
		})
	}
	service, mock := newBulkMailTestService(t)
	mock.ExpectQuery(regexp.QuoteMeta(bulkMailExclusionQuery)).WillReturnError(errors.New("database unavailable"))
	if _, err := service.PreviewUserMail(context.Background(), UserMailRequest{}); err == nil {
		t.Fatal("database failure must prevent recipient query")
	}
	service.nodeAddressEnsureErr = errors.New("schema unavailable")
	if _, err := service.PreviewUserMail(context.Background(), UserMailRequest{}); err == nil {
		t.Fatal("schema failure must prevent recipient query")
	}
}

func TestSendUserMailRejectsZeroEligibleRecipients(t *testing.T) {
	service, mock := newBulkMailTestService(t)
	service.jobs = &captureQueue{}
	expectMailExclusions(mock, `["1"]`, `[]`)
	mock.ExpectQuery(`SELECT u.id, u.email FROM v2_user u`).WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).AddRow(1, "a@example.com").AddRow(2, ""))
	ok, err := service.SendUserMail(context.Background(), UserMailRequest{Subject: "Notice", Content: "Hello"})
	if ok || err == nil || !strings.Contains(err.Error(), "没有可发送用户") || len(service.jobs.(*captureQueue).jobs) != 0 {
		t.Fatalf("zero recipients must reject send: %v, %v", ok, err)
	}
}

func TestSendUserMailRechecksQueuedRecipients(t *testing.T) {
	oldRoot := adminProjectRoot
	adminProjectRoot = t.TempDir()
	t.Cleanup(func() { adminProjectRoot = oldRoot })
	service, mock := newBulkMailTestService(t)
	batchQueue := &captureQueue{}
	service.jobs = batchQueue
	service.cfg.MailHost = "smtp.invalid"
	expectMailExclusions(mock, `["2"]`, `[]`)
	mock.ExpectQuery(`SELECT u.id, u.email FROM v2_user u`).WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).AddRow(1, "a@example.com").AddRow(2, "b@example.com").AddRow(3, "c@example.com"))
	ok, err := service.SendUserMail(context.Background(), UserMailRequest{Subject: "Notice", Content: "Hello"})
	if !ok || err != nil || len(batchQueue.jobs) != 1 {
		t.Fatalf("enqueue: %v, %v", ok, err)
	}
	expectMailRecipient(mock, 1, "a@example.com")
	expectMailExclusions(mock, `["1"]`, `[]`)
	expectAllowedMail(mock, 3, "c@example.com", nil)
	var sent []string
	service.mailSender = func(host string, port int, encryption, username, password, from, fromName, to, subject, body string) error {
		sent = append(sent, to)
		return nil
	}
	if err := batchQueue.jobs[0](context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sent, []string{"c@example.com"}) {
		t.Fatalf("newly excluded user sent or initially excluded user re-added: %v", sent)
	}
}

func TestBulkMailRechecksAfterThrottle(t *testing.T) {
	service, mock := newBulkMailTestService(t)
	expectAllowedMail(mock, 1, "a@example.com", nil)
	waits, sends := 0, 0
	service.sleep = func(ctx context.Context, duration time.Duration) error {
		waits++
		expectMailRecipient(mock, 2, "b@example.com")
		expectMailExclusions(mock, `[]`, `["2-10"]`)
		return nil
	}
	service.mailSender = func(host string, port int, encryption, username, password, from, fromName, to, subject, body string) error {
		sends++
		return nil
	}
	err := service.dispatchUserMailJobs(context.Background(), []bulkMailRecipient{{1, "a@example.com"}, {2, "b@example.com"}}, "Notice", "Hello", bulkMailConfig{host: "smtp.invalid", bulkIntervalSeconds: 2})
	if err != nil || waits != 1 || sends != 1 {
		t.Fatalf("recheck after throttle: sends=%d waits=%d err=%v", sends, waits, err)
	}
}

func TestBulkMailSkipsChangedAndDeletedRecipients(t *testing.T) {
	service, mock := newBulkMailTestService(t)
	expectMailRecipient(mock, 1, "changed@example.com")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT email FROM v2_user WHERE id = $1`)).WithArgs(int64(2)).WillReturnRows(sqlmock.NewRows([]string{"email"}))
	if err := service.dispatchUserMailJobs(context.Background(), []bulkMailRecipient{{1, "a@example.com"}, {2, "b@example.com"}}, "Notice", "Hello", bulkMailConfig{host: "smtp.invalid"}); err != nil {
		t.Fatal(err)
	}
}

func TestBulkMailStopsRemainingOnCheckFailure(t *testing.T) {
	service, mock := newBulkMailTestService(t)
	expectAllowedMail(mock, 1, "a@example.com", nil)
	expectMailRecipient(mock, 2, "b@example.com")
	mock.ExpectQuery(regexp.QuoteMeta(bulkMailExclusionQuery)).WillReturnError(errors.New("database unavailable"))
	var sends int
	service.mailSender = func(host string, port int, encryption, username, password, from, fromName, to, subject, body string) error {
		sends++
		return nil
	}
	err := service.dispatchUserMailJobs(context.Background(), []bulkMailRecipient{{1, "a@example.com"}, {2, "b@example.com"}, {3, "c@example.com"}}, "Notice", "Hello", bulkMailConfig{host: "smtp.invalid"})
	if err == nil || sends != 1 {
		t.Fatalf("failed check must stop remaining recipients: sends=%d err=%v", sends, err)
	}
}

func TestBulkMailDoesNotFallbackOnQueueFailure(t *testing.T) {
	service, _ := newBulkMailTestService(t)
	queueErr := errors.New("queue full")
	service.jobs = &captureQueue{err: queueErr}
	err := service.dispatchUserMailJobs(context.Background(), []bulkMailRecipient{{1, "a@example.com"}}, "Notice", "Hello", bulkMailConfig{host: "smtp.invalid"})
	if !errors.Is(err, queueErr) {
		t.Fatalf("expected enqueue error without synchronous fallback: %v", err)
	}
}

func TestBulkMailReturnsSynchronousSMTPError(t *testing.T) {
	service, mock := newBulkMailTestService(t)
	sendErr := errors.New("SMTP rejected")
	expectAllowedMail(mock, 1, "a@example.com", sendErr)
	service.mailSender = func(host string, port int, encryption, username, password, from, fromName, to, subject, body string) error {
		return sendErr
	}
	err := service.dispatchUserMailJobs(context.Background(), []bulkMailRecipient{{1, "a@example.com"}}, "Notice", "Hello", bulkMailConfig{host: "smtp.invalid"})
	if !errors.Is(err, sendErr) {
		t.Fatalf("SMTP error swallowed: %v", err)
	}
}

func TestBulkMailCancellationPreventsSend(t *testing.T) {
	service, _ := newBulkMailTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := service.dispatchUserMailJobs(ctx, []bulkMailRecipient{{1, "a@example.com"}}, "Notice", "Hello", bulkMailConfig{host: "smtp.invalid"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}
