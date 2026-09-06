package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
)

type smtpTransport struct {
	config  config.EmailConfig
	rootCAs *x509.CertPool
}

func (s *smtpTransport) send(ctx context.Context, message Message) error {
	settings := s.config.SMTP
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(settings.Host, strconv.Itoa(settings.Port)))
	if err != nil {
		return deliveryError("SMTP", "connection")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsConfig := &tls.Config{ServerName: settings.Host, MinVersion: tls.VersionTLS12, RootCAs: s.rootCAs}
	var smtpConn net.Conn = conn
	if settings.TLSMode == "tls" {
		secure := tls.Client(conn, tlsConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return deliveryError("SMTP", "TLS handshake")
		}
		smtpConn = secure
	}
	client, err := smtp.NewClient(smtpConn, settings.Host)
	if err != nil {
		return deliveryError("SMTP", "greeting")
	}
	defer client.Close()
	if settings.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return deliveryError("SMTP", "required STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return deliveryError("SMTP", "STARTTLS handshake")
		}
	}
	if settings.Username != "" {
		// net/smtp refuses PLAIN credentials without authenticated TLS.
		if err := client.Auth(smtp.PlainAuth("", settings.Username, settings.Password, settings.Host)); err != nil {
			return deliveryError("SMTP", "authentication (AUTH PLAIN)")
		}
	}
	if err := client.Mail(s.config.FromAddress); err != nil {
		return deliveryError("SMTP", "sender")
	}
	if err := client.Rcpt(message.To); err != nil {
		return deliveryError("SMTP", "recipient")
	}
	data, err := encodeMIME(s.config, message)
	if err != nil {
		return deliveryError("SMTP", "message encoding")
	}
	writer, err := client.Data()
	if err != nil {
		return deliveryError("SMTP", "DATA")
	}
	if _, err := writer.Write(data); err != nil {
		return deliveryError("SMTP", "message write")
	}
	if err := writer.Close(); err != nil {
		return deliveryError("SMTP", "message acceptance")
	}
	// A failed QUIT after DATA acceptance must not turn success into a retry.
	_ = client.Quit()
	return nil
}

func encodeMIME(c config.EmailConfig, m Message) ([]byte, error) {
	var out bytes.Buffer
	from := (&mail.Address{Name: c.FromName, Address: c.FromAddress}).String()
	fmt.Fprintf(&out, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\n", from, (&mail.Address{Address: m.To}).String(), mime.QEncoding.Encode("UTF-8", m.Subject), time.Now().UTC().Format(time.RFC1123Z), uuid.NewString(), strings.Split(c.FromAddress, "@")[1])
	if c.ReplyTo != "" {
		fmt.Fprintf(&out, "Reply-To: %s\r\n", (&mail.Address{Address: c.ReplyTo}).String())
	}
	if len(m.Attachments) > 0 {
		multi := multipart.NewWriter(&out)
		fmt.Fprintf(&out, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", multi.Boundary())
		body := m
		body.Attachments = nil
		encoded, err := encodeMIME(c, body)
		if err != nil {
			return nil, err
		}
		// Nest the already encoded body, retaining multipart/alternative when present.
		parsed, err := mail.ReadMessage(bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		headers := textproto.MIMEHeader{}
		for _, key := range []string{"Content-Type", "Content-Transfer-Encoding"} {
			if v := parsed.Header.Get(key); v != "" {
				headers.Set(key, v)
			}
		}
		part, err := multi.CreatePart(headers)
		if err != nil {
			return nil, err
		}
		if _, err = io.Copy(part, parsed.Body); err != nil {
			return nil, err
		}
		for _, a := range m.Attachments {
			part, err := multi.CreatePart(textproto.MIMEHeader{"Content-Type": {a.ContentType}, "Content-Disposition": {mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename})}, "Content-Transfer-Encoding": {"base64"}})
			if err != nil {
				return nil, err
			}
			data := base64.StdEncoding.EncodeToString(a.Data)
			for len(data) > 0 {
				n := min(76, len(data))
				if _, err = fmt.Fprint(part, data[:n]+"\r\n"); err != nil {
					return nil, err
				}
				data = data[n:]
			}
		}
		if err := multi.Close(); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	}
	if m.Text != "" && m.HTML != "" {
		multi := multipart.NewWriter(&out)
		fmt.Fprintf(&out, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", multi.Boundary())
		for _, part := range []struct{ kind, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
			writer, err := multi.CreatePart(textproto.MIMEHeader{"Content-Type": {part.kind + "; charset=UTF-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
			if err != nil {
				return nil, err
			}
			encoded := quotedprintable.NewWriter(writer)
			if _, err := encoded.Write([]byte(part.body)); err != nil {
				return nil, err
			}
			if err := encoded.Close(); err != nil {
				return nil, err
			}
		}
		if err := multi.Close(); err != nil {
			return nil, err
		}
	} else {
		kind, body := "text/plain", m.Text
		if m.HTML != "" {
			kind, body = "text/html", m.HTML
		}
		fmt.Fprintf(&out, "Content-Type: %s; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", kind)
		encoded := quotedprintable.NewWriter(&out)
		if _, err := encoded.Write([]byte(body)); err != nil {
			return nil, err
		}
		if err := encoded.Close(); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}
