// Package email provides interchangeable transactional email transports.
package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/AutisticShark/ObjectShare/config"
)

var ErrDisabled = errors.New("email delivery is disabled")

// Message targets one mailbox. At least one body is required. Limits are shared
// across providers: 100 subject characters and 80 KiB per UTF-8 body.
type Message struct{ To, Subject, Text, HTML string }

// Sender implementations are safe for concurrent use. Success means the
// transport accepted the message, not that it reached the recipient's inbox.
// Sends are not retried automatically: a timeout can occur after acceptance.
type Sender interface {
	Send(context.Context, Message) error
}
type transport interface {
	send(context.Context, Message) error
}
type sender struct {
	config    config.EmailConfig
	transport transport
}

func New(ctx context.Context, settings *config.EmailConfig) (Sender, error) {
	c := config.EmailConfig{}
	if settings != nil {
		c = *settings
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	s := &sender{config: c}
	client := &http.Client{Timeout: c.Timeout.Duration(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	switch c.Provider {
	case "smtp":
		s.transport = &smtpTransport{config: c}
	case "alibaba":
		s.transport = &alibabaTransport{config: c, client: client}
	case "ses":
		backend, err := newSESTransport(ctx, c, client)
		if err != nil {
			return nil, err
		}
		s.transport = backend
	}
	return s, nil
}

func (s *sender) Send(ctx context.Context, message Message) error {
	if s.transport == nil {
		return ErrDisabled
	}
	if !config.ValidEmailAddress(message.To) {
		return errors.New("email recipient must be a single ASCII email address")
	}
	if !utf8.ValidString(message.Subject) || strings.TrimSpace(message.Subject) == "" || utf8.RuneCountInString(message.Subject) > 100 || strings.ContainsAny(message.Subject, "\r\n\x00") {
		return errors.New("email subject must contain 1 to 100 characters and no line breaks")
	}
	if message.Text == "" && message.HTML == "" {
		return errors.New("email requires a text or HTML body")
	}
	for _, body := range []string{message.Text, message.HTML} {
		if !utf8.ValidString(body) || strings.ContainsRune(body, 0) || len(body) > 80*1024 {
			return errors.New("email bodies must be valid UTF-8 and at most 80 KiB each, without NUL bytes")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout.Duration())
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.transport.send(ctx, message)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Provider responses can echo credentials or message content. Return only a
// locally generated stage/status description, never raw bodies or URL errors.
func deliveryError(provider, stage string) error {
	return fmt.Errorf("%s email: %s failed", provider, stage)
}

func httpStatus(code int) string { return strconv.Itoa(code) }

func decodeProviderResponse(body io.Reader, result any) bool {
	const limit = 64 * 1024
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	return err == nil && len(data) <= limit && json.Unmarshal(data, result) == nil
}
