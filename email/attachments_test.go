package email

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestInvoiceAttachmentMIMERoundTrip(t *testing.T) {
	pdf := []byte("%PDF-1.4\n" + strings.Repeat("invoice bytes\x00", 100))
	encoded, err := encodeMIME(testConfig("smtp"), Message{To: "buyer@example.com", Subject: "Paid invoice", Text: "Payment confirmed", HTML: "<p>Payment confirmed</p>", Attachments: []Attachment{{Filename: "invoice.pdf", ContentType: "application/pdf", Data: pdf}}})
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	kind, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/mixed" {
		t.Fatalf("mixed: %s %v", kind, err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	body, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Header.Get("Content-Type"), "multipart/alternative") {
		t.Fatal("lost alternative body")
	}
	attachment, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if attachment.FileName() != "invoice.pdf" || attachment.Header.Get("Content-Type") != "application/pdf" {
		t.Fatal("lost attachment metadata")
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, attachment))
	if err != nil || !bytes.Equal(decoded, pdf) {
		t.Fatal("attachment bytes changed")
	}
	if _, err = reader.NextPart(); err != io.EOF {
		t.Fatal("unexpected MIME part")
	}
}

func TestSESInvoiceAttachmentRawPayload(t *testing.T) {
	c := testConfig("ses")
	calls := 0
	backend := &sesTransport{config: c, credentials: credentials.NewStaticCredentialsProvider("key", "secret", ""), client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var payload struct {
			Content struct {
				Raw    struct{ Data []byte }
				Simple json.RawMessage
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Content.Simple) != 0 || !bytes.Contains(payload.Content.Raw.Data, []byte("multipart/mixed")) || !bytes.Contains(payload.Content.Raw.Data, []byte("filename=invoice.pdf")) {
			t.Fatal("SES lost raw attachment")
		}
		return response(200, `{"MessageId":"accepted"}`), nil
	})}}
	if err := backend.send(t.Context(), Message{To: "buyer@example.com", Subject: "Paid", Text: "Confirmed", Attachments: []Attachment{{Filename: "invoice.pdf", ContentType: "application/pdf", Data: []byte("%PDF-")}}}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("unexpected SES retries")
	}
}

func TestAttachmentValidation(t *testing.T) {
	calls := 0
	sender := &sender{config: testConfig("smtp"), transport: transportFunc(func(context.Context, Message) error { calls++; return nil })}
	for _, attachment := range []Attachment{
		{Filename: "bad\r\nBcc: other@example.com", ContentType: "application/pdf", Data: []byte("pdf")},
		{Filename: "../invoice.pdf", ContentType: "application/pdf", Data: []byte("pdf")},
		{Filename: "invoice.pdf", ContentType: "text/html", Data: []byte("pdf")},
		{Filename: "invoice.pdf", ContentType: "application/pdf", Data: make([]byte, 4*1024*1024+1)},
	} {
		if err := sender.Send(t.Context(), Message{To: "buyer@example.com", Subject: "Paid", Text: "Paid", Attachments: []Attachment{attachment}}); err == nil {
			t.Fatal("invalid attachment sent")
		}
	}
	if calls != 0 {
		t.Fatal("transport called before validation")
	}
}
