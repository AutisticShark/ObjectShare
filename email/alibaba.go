package email

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // Required by the Direct Mail RPC signature protocol.
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
)

type alibabaTransport struct {
	config config.EmailConfig
	client *http.Client
}

func (s *alibabaTransport) send(ctx context.Context, m Message) error {
	c := s.config
	params := url.Values{
		"Action": {"SingleSendMail"}, "Version": {"2015-11-23"}, "Format": {"JSON"},
		"AccessKeyId": {c.Alibaba.AccessKeyID}, "RegionId": {c.Alibaba.Region},
		"SignatureMethod": {"HMAC-SHA1"}, "SignatureVersion": {"1.0"},
		"SignatureNonce": {uuid.NewString()}, "Timestamp": {time.Now().UTC().Format("2006-01-02T15:04:05Z")},
		"AccountName": {c.FromAddress}, "AddressType": {"1"}, "ReplyToAddress": {"false"},
		"ToAddress": {m.To}, "Subject": {m.Subject}, "ClickTrace": {"0"},
	}
	if c.FromName != "" {
		params.Set("FromAlias", c.FromName)
	}
	if c.ReplyTo != "" {
		params.Set("ReplyAddress", c.ReplyTo)
	}
	if m.Text != "" {
		params.Set("TextBody", m.Text)
	}
	if m.HTML != "" {
		params.Set("HtmlBody", m.HTML)
	}
	params.Set("Signature", alibabaSignature(params, c.Alibaba.AccessKeySecret))
	host := "dm." + c.Alibaba.Region + ".aliyuncs.com"
	if c.Alibaba.Region == "cn-hangzhou" {
		host = "dm.aliyuncs.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/", strings.NewReader(params.Encode()))
	if err != nil {
		return deliveryError("Alibaba", "request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return deliveryError("Alibaba", "request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return deliveryError("Alibaba", "provider acceptance (HTTP "+httpStatus(resp.StatusCode)+")")
	}
	var result struct {
		EnvID     string `json:"EnvId"`
		RequestID string `json:"RequestId"`
		Code      string `json:"Code"`
	}
	if !decodeProviderResponse(resp.Body, &result) || result.Code != "" || result.EnvID == "" || result.RequestID == "" {
		return deliveryError("Alibaba", "provider response")
	}
	return nil
}

func alibabaSignature(params url.Values, secret string) string {
	canonical := strings.ReplaceAll(params.Encode(), "+", "%20")
	toSign := "POST&%2F&" + strings.ReplaceAll(url.QueryEscape(canonical), "+", "%20")
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte(toSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
