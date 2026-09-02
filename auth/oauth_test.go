package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestOAuthProviderUsesStatePKCEAndVerifiedGoogleProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			if err := request.ParseForm(); err != nil || request.FormValue("code") != "authorization-code" || request.FormValue("code_verifier") != "verifier-value" {
				t.Errorf("invalid token exchange: form=%v err=%v", request.Form, err)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"access_token":"provider-token","token_type":"Bearer"}`))
		case "/userinfo":
			if request.Header.Get("Authorization") != "Bearer provider-token" {
				t.Errorf("userinfo authorization = %q", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"sub": "google-subject", "email": "user@example.com", "email_verified": true, "name": "OAuth User"})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	provider := &oauthProvider{key: "google", label: "Google", config: oauth2.Config{
		ClientID: "client", ClientSecret: "secret", RedirectURL: "https://share.example.com/oauth/google/callback",
		Scopes: []string{"openid", "email", "profile"}, Endpoint: oauth2.Endpoint{AuthURL: server.URL + "/authorize", TokenURL: server.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
	}, profileURL: server.URL + "/userinfo", httpClient: server.Client()}
	authorizationURL, err := url.Parse(provider.AuthorizationURL("state-value", "verifier-value"))
	if err != nil {
		t.Fatal(err)
	}
	query := authorizationURL.Query()
	if query.Get("state") != "state-value" || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("redirect_uri") != provider.config.RedirectURL {
		t.Fatalf("authorization query is incomplete: %v", query)
	}
	profile, err := provider.Profile(context.Background(), "authorization-code", "verifier-value")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Subject != "google-subject" || profile.Email != "user@example.com" || !profile.EmailVerified || profile.DisplayName != "OAuth User" {
		t.Fatalf("unexpected Google profile: %#v", profile)
	}
}

func TestGitHubProfileUsesStableIDAndVerifiedPrimaryEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			writer.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = writer.Write([]byte("access_token=github-token&token_type=bearer"))
		case "/user":
			_, _ = writer.Write([]byte(`{"id":123456,"login":"octocat","name":""}`))
		case "/emails":
			_, _ = writer.Write([]byte(`[{"email":"unverified@example.com","primary":true,"verified":false},{"email":"verified@example.com","primary":true,"verified":true}]`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := &oauthProvider{key: "github", label: "GitHub", config: oauth2.Config{
		ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
	}, profileURL: server.URL + "/user", emailsURL: server.URL + "/emails", httpClient: server.Client()}
	profile, err := provider.Profile(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Subject != "123456" || profile.Email != "verified@example.com" || !profile.EmailVerified || profile.DisplayName != "octocat" {
		t.Fatalf("unexpected GitHub profile: %#v", profile)
	}
}

func TestOAuthProviderRejectsTrailingProfileData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/token" {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"sub":"subject"}{"sub":"second"}`))
	}))
	defer server.Close()
	provider := &oauthProvider{key: "google", config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}}, profileURL: server.URL, httpClient: server.Client()}
	_, err := provider.Profile(context.Background(), "code", "verifier")
	if err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing provider data error = %v", err)
	}
}
