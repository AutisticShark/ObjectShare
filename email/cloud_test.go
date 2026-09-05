package email

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestAlibabaPublishedSignatureVector(t *testing.T) {
	// Alibaba's published POST signature example, including reserved characters.
	p := url.Values{"AccessKeyId": {"testid"}, "AccountName": {"<a%b'>"}, "Action": {"SingleSendMail"}, "AddressType": {"1"}, "Format": {"XML"}, "HtmlBody": {"4"}, "RegionId": {"cn-hangzhou"}, "ReplyToAddress": {"true"}, "SignatureMethod": {"HMAC-SHA1"}, "SignatureNonce": {"c1b2c332-4cfb-4a0f-b8cc-ebe622aa0a5c"}, "SignatureVersion": {"1.0"}, "Subject": {"3"}, "TagName": {"2"}, "Timestamp": {"2016-10-20T06:27:56Z"}, "ToAddress": {"1@test.com"}, "Version": {"2015-11-23"}}
	if got := alibabaSignature(p, "testsecret"); got != "llJfXJjBW3OacrVgxxsITgYaYm0=" {
		t.Fatalf("signature = %q", got)
	}
}

func TestAlibabaNativeRequest(t *testing.T) {
	for _, region := range []string{"cn-hangzhou", "ap-southeast-1", "ap-southeast-2", "us-east-1", "eu-central-1"} {
		t.Run(region, func(t *testing.T) {
			c := testConfig("alibaba")
			c.Alibaba.Region = region
			nonces := map[string]bool{}
			backend := &alibabaTransport{config: c, client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				wantHost := "dm." + region + ".aliyuncs.com"
				if region == "cn-hangzhou" {
					wantHost = "dm.aliyuncs.com"
				}
				if r.Method != "POST" || r.URL.Scheme != "https" || r.URL.Host != wantHost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Fatal("wrong Alibaba endpoint or method")
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				p := r.PostForm
				signature := p.Get("Signature")
				p.Del("Signature")
				if signature != alibabaSignature(p, c.Alibaba.AccessKeySecret) {
					t.Fatal("request signature mismatch")
				}
				for k, v := range map[string]string{"AccountName": c.FromAddress, "FromAlias": c.FromName, "ReplyAddress": c.ReplyTo, "AddressType": "1", "ReplyToAddress": "false", "ClickTrace": "0", "Action": "SingleSendMail", "Version": "2015-11-23", "RegionId": region, "Subject": "你好 + & test", "TextBody": "plain body", "HtmlBody": "<p>html</p>", "ToAddress": "recipient@example.com"} {
					if p.Get(k) != v {
						t.Fatalf("field %s mismatch", k)
					}
				}
				if p.Get("Timestamp") == "" || p.Get("SignatureNonce") == "" || nonces[p.Get("SignatureNonce")] {
					t.Fatal("missing or reused replay protection")
				}
				nonces[p.Get("SignatureNonce")] = true
				return response(200, `{"EnvId":"env-id","RequestId":"request-id"}`), nil
			})}}
			for range 2 {
				if err := backend.send(t.Context(), Message{To: "recipient@example.com", Subject: "你好 + & test", Text: "plain body", HTML: "<p>html</p>"}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSESNativeRequestAndSigning(t *testing.T) {
	for _, region := range []string{"us-east-1", "cn-north-1", "us-gov-west-1"} {
		t.Run(region, func(t *testing.T) {
			c := testConfig("ses")
			c.SES.Region = region
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				domain := "amazonaws.com"
				if strings.HasPrefix(region, "cn-") {
					domain += ".cn"
				}
				if r.Method != "POST" || r.URL.String() != "https://email."+region+"."+domain+"/v2/email/outbound-emails" {
					t.Fatal("incorrect SES API request")
				}
				auth := r.Header.Get("Authorization")
				if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=access-id/") || !strings.Contains(auth, "/"+region+"/ses/aws4_request") || r.Header.Get("X-Amz-Date") == "" || r.Header.Get("X-Amz-Security-Token") != "session-secret" {
					t.Fatal("missing SES SigV4 signing or temporary token")
				}
				var p struct {
					FromEmailAddress     string
					Destination          struct{ ToAddresses []string }
					ReplyToAddresses     []string
					ConfigurationSetName string
					Content              struct {
						Simple struct {
							Subject struct{ Data, Charset string }
							Body    struct {
								Text, Html struct{ Data, Charset string }
							}
						}
					}
				}
				if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
					t.Fatal(err)
				}
				if p.FromEmailAddress != `"ObjectShare" <sender@example.com>` || len(p.Destination.ToAddresses) != 1 || p.Destination.ToAddresses[0] != "recipient@example.com" || p.ConfigurationSetName != "events" || len(p.ReplyToAddresses) != 1 || p.ReplyToAddresses[0] != c.ReplyTo || p.Content.Simple.Subject.Data != "你好" || p.Content.Simple.Subject.Charset != "UTF-8" || p.Content.Simple.Body.Text.Data != "plain" || p.Content.Simple.Body.Html.Data != "<p>html</p>" {
					t.Fatalf("SES payload mismatch: %+v", p)
				}
				return response(200, `{"MessageId":"message-id"}`), nil
			})}
			s, err := newSESTransport(t.Context(), c, client)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.send(t.Context(), Message{To: "recipient@example.com", Subject: "你好", Text: "plain", HTML: "<p>html</p>"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSESDefaultCredentialChain(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "chain-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "chain-secret")
	t.Setenv("AWS_SESSION_TOKEN", "chain-token")
	c := testConfig("ses")
	c.SES.AccessKeyID = ""
	c.SES.SecretAccessKey = ""
	c.SES.SessionToken = ""
	s, err := newSESTransport(t.Context(), c, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKeyID != "chain-id" || got.SecretAccessKey != "chain-secret" || got.SessionToken != "chain-token" {
		t.Fatal("AWS default chain not used")
	}
}

func TestCloudProvidersDoNotFollowRedirects(t *testing.T) {
	for _, provider := range []string{"alibaba", "ses"} {
		t.Run(provider, func(t *testing.T) {
			c := testConfig(provider)
			configured, err := New(t.Context(), &c)
			if err != nil {
				t.Fatal(err)
			}
			s := configured.(*sender)
			var client *http.Client
			switch backend := s.transport.(type) {
			case *alibabaTransport:
				client = backend.client
			case *sesTransport:
				client = backend.client
			}
			calls := 0
			client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				resp := response(307, "")
				resp.Header.Set("Location", "https://attacker.example/collect")
				return resp, nil
			})
			if err := s.Send(t.Context(), Message{To: "recipient@example.com", Subject: "test", Text: "body"}); err == nil || calls != 1 {
				t.Fatal("signed email request followed a redirect")
			}
		})
	}
}

func TestCloudFailuresAreBoundedRedactedAndNotRetried(t *testing.T) {
	for _, provider := range []string{"alibaba", "ses"} {
		for _, tc := range []struct {
			name string
			code int
			body string
			err  error
		}{
			{"rejection", 403, `{"Message":"secret-echo"}`, nil},
			{"throttle", 429, `secret-echo`, nil},
			{"redirect", 307, `secret-echo`, nil},
			{"invalid success", 200, `{"Code":"secret-echo"}`, nil},
			{"malformed", 200, `secret-echo`, nil},
			{"trailing data", 200, `{"MessageId":"id","EnvId":"id","RequestId":"id"} secret-echo`, nil},
			{"oversized", 200, strings.Repeat(" ", 64*1024) + `{"MessageId":"late","EnvId":"late","RequestId":"late"}`, nil},
			{"network", 0, "", errors.New("secret-echo")},
		} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					if tc.err != nil {
						return nil, tc.err
					}
					return response(tc.code, tc.body), nil
				})}
				c := testConfig(provider)
				var backend transport = &alibabaTransport{config: c, client: client}
				if provider == "ses" {
					backend = &sesTransport{config: c, client: client, credentials: credentials.NewStaticCredentialsProvider("id", "secret", "token")}
				}
				err := backend.send(context.Background(), Message{To: "recipient@example.com", Subject: "test", Text: "body"})
				if err == nil || strings.Contains(err.Error(), "secret-echo") {
					t.Fatal("failure accepted or provider response leaked")
				}
				if calls != 1 {
					t.Fatal("provider was retried")
				}
			})
		}
	}
}
