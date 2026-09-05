package email

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
)

type transportFunc func(context.Context, Message) error

func (f transportFunc) send(ctx context.Context, m Message) error { return f(ctx, m) }

func testConfig(provider string) config.EmailConfig {
	c := config.EmailConfig{Provider: provider, FromAddress: "sender@example.com", FromName: "ObjectShare", ReplyTo: "reply@example.com",
		SMTP:    config.SMTPConfig{Host: "smtp.example.com", Username: "user", Password: "secret"},
		Alibaba: config.AlibabaMailConfig{AccessKeyID: "access-id", AccessKeySecret: "access-secret"},
		SES:     config.SESConfig{AccessKeyID: "access-id", SecretAccessKey: "access-secret", SessionToken: "session-secret", ConfigurationSet: "events"}}
	_ = c.Validate()
	return c
}

func TestFactoryAndDisabled(t *testing.T) {
	for _, provider := range []string{"none", "smtp", "alibaba", "ses"} {
		t.Run(provider, func(t *testing.T) {
			c := testConfig(provider)
			s, err := New(t.Context(), &c)
			if err != nil {
				t.Fatal(err)
			}
			if provider == "none" && !errors.Is(s.Send(t.Context(), Message{}), ErrDisabled) {
				t.Fatal("disabled provider sent")
			}
		})
	}
	s, err := New(t.Context(), nil)
	if err != nil || !errors.Is(s.Send(t.Context(), Message{}), ErrDisabled) {
		t.Fatal("nil config must disable")
	}
	c := testConfig("invalid")
	if _, err := New(t.Context(), &c); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestMessageValidationBeforeTransport(t *testing.T) {
	calls := 0
	s := &sender{config: testConfig("smtp"), transport: transportFunc(func(context.Context, Message) error { calls++; return nil })}
	for _, m := range []Message{
		{To: "a@example.com,b@example.com", Subject: "test", Text: "body"},
		{To: `"a,b"@example.com`, Subject: "test", Text: "body"},
		{To: "a@example.com\r\nBcc: b@example.com", Subject: "test", Text: "body"},
		{To: "a@example.com", Subject: "test\r\nBcc: b@example.com", Text: "body"},
		{To: "a@example.com", Subject: strings.Repeat("字", 101), Text: "body"},
		{To: "a@example.com", Subject: "test"},
		{To: "a@example.com", Subject: "test", HTML: strings.Repeat("x", 80*1024+1)},
		{To: "a@example.com", Subject: "test", Text: "bad\x00body"},
		{To: "a@example.com", Subject: "test", Text: string([]byte{255})},
	} {
		if err := s.Send(t.Context(), m); err == nil {
			t.Fatal("invalid message accepted")
		}
	}
	if calls != 0 {
		t.Fatal("transport invoked before validation")
	}
	if err := s.Send(t.Context(), Message{To: "a@example.com", Subject: "你好", Text: "hello", HTML: "<p>hello</p>"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("valid message not sent exactly once")
	}
}

func TestSendCancellationAndNoRetry(t *testing.T) {
	calls := 0
	s := &sender{config: testConfig("smtp"), transport: transportFunc(func(ctx context.Context, _ Message) error {
		calls++
		<-ctx.Done()
		return errors.New("ambiguous delivery failure")
	})}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := s.Send(ctx, Message{To: "a@example.com", Subject: "test", Text: "body"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("send retried")
	}
	if err := s.Send(ctx, Message{To: "a@example.com", Subject: "test", Text: "body"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("canceled context reached provider")
	}
}
