package email

import (
	"bytes"
	"context"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	dm "github.com/alibabacloud-go/dm-20151123/v2/client"
	"github.com/alibabacloud-go/tea/dara"
)

// Alibaba requires its upload-capable SDK for attachments. Keep the existing
// signed SingleSendMail transport for messages without files.
func (s *alibabaTransport) sendAttachments(ctx context.Context, m Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	host := "dm." + s.config.Alibaba.Region + ".aliyuncs.com"
	if s.config.Alibaba.Region == "cn-hangzhou" {
		host = "dm.aliyuncs.com"
	}
	client, err := dm.NewClient(&openapi.Config{AccessKeyId: dara.String(s.config.Alibaba.AccessKeyID), AccessKeySecret: dara.String(s.config.Alibaba.AccessKeySecret), RegionId: dara.String(s.config.Alibaba.Region), Endpoint: dara.String(host), Protocol: dara.String("HTTPS")})
	if err != nil {
		return deliveryError("Alibaba", "attachment client")
	}
	request := &dm.SingleSendMailAdvanceRequest{AccountName: dara.String(s.config.FromAddress), AddressType: dara.Int32(1), ReplyToAddress: dara.Bool(false), ToAddress: dara.String(m.To), Subject: dara.String(m.Subject), TextBody: dara.String(m.Text), HtmlBody: dara.String(m.HTML), FromAlias: dara.String(s.config.FromName), ClickTrace: dara.String("0")}
	if s.config.ReplyTo != "" {
		request.ReplyAddress = dara.String(s.config.ReplyTo)
	}
	for _, a := range m.Attachments {
		request.Attachments = append(request.Attachments, &dm.SingleSendMailAdvanceRequestAttachments{AttachmentName: dara.String(a.Filename), AttachmentUrlObject: bytes.NewReader(a.Data)})
	}
	// Each of the SDK's authorization, upload and send stages has a bounded
	// timeout; automatic retries are disabled to avoid repeating accepted email.
	timeout := s.config.Timeout.Duration()
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline)/3)
	}
	if timeout <= 0 {
		return context.DeadlineExceeded
	}
	milliseconds := int(timeout.Milliseconds())
	if milliseconds < 1 {
		milliseconds = 1
	}
	response, err := client.SingleSendMailAdvance(request, &dara.RuntimeOptions{Autoretry: dara.Bool(false), ReadTimeout: dara.Int(milliseconds), ConnectTimeout: dara.Int(milliseconds)})
	if err != nil || response == nil || response.Body == nil || dara.StringValue(response.Body.EnvId) == "" {
		return deliveryError("Alibaba", "attachment delivery")
	}
	return nil
}
