package email

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type sesTransport struct {
	config      config.EmailConfig
	credentials aws.CredentialsProvider
	client      *http.Client
}

func newSESTransport(ctx context.Context, c config.EmailConfig, client *http.Client) (*sesTransport, error) {
	var provider aws.CredentialsProvider
	if c.SES.AccessKeyID != "" {
		provider = credentials.NewStaticCredentialsProvider(c.SES.AccessKeyID, c.SES.SecretAccessKey, c.SES.SessionToken)
	} else {
		ctx, cancel := context.WithTimeout(ctx, c.Timeout.Duration())
		defer cancel()
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.SES.Region))
		if err != nil {
			return nil, deliveryError("SES", "credential configuration")
		}
		provider = awsCfg.Credentials
	}
	return &sesTransport{config: c, credentials: provider, client: client}, nil
}

func (s *sesTransport) send(ctx context.Context, m Message) error {
	content := func(data string) map[string]string { return map[string]string{"Data": data, "Charset": "UTF-8"} }
	body := map[string]any{}
	if m.Text != "" {
		body["Text"] = content(m.Text)
	}
	if m.HTML != "" {
		body["Html"] = content(m.HTML)
	}
	payload := map[string]any{
		"FromEmailAddress": (&mail.Address{Name: s.config.FromName, Address: s.config.FromAddress}).String(),
		"Destination":      map[string]any{"ToAddresses": []string{m.To}},
		"Content":          map[string]any{"Simple": map[string]any{"Subject": content(m.Subject), "Body": body}},
	}
	if s.config.ReplyTo != "" {
		payload["ReplyToAddresses"] = []string{s.config.ReplyTo}
	}
	if s.config.SES.ConfigurationSet != "" {
		payload["ConfigurationSetName"] = s.config.SES.ConfigurationSet
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return deliveryError("SES", "message encoding")
	}
	domain := "amazonaws.com"
	if strings.HasPrefix(s.config.SES.Region, "cn-") {
		domain = "amazonaws.com.cn"
	}
	endpoint := "https://email." + s.config.SES.Region + "." + domain + "/v2/email/outbound-emails"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return deliveryError("SES", "request")
	}
	req.Header.Set("Content-Type", "application/json")
	creds, err := s.credentials.Retrieve(ctx)
	if err != nil {
		return deliveryError("SES", "credentials")
	}
	digest := sha256.Sum256(data)
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(digest[:]), "ses", s.config.SES.Region, time.Now().UTC()); err != nil {
		return deliveryError("SES", "request signing")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return deliveryError("SES", "request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return deliveryError("SES", "provider acceptance (HTTP "+httpStatus(resp.StatusCode)+")")
	}
	var result struct {
		MessageID string `json:"MessageId"`
	}
	if !decodeProviderResponse(resp.Body, &result) || result.MessageID == "" {
		return deliveryError("SES", "provider response")
	}
	return nil
}
