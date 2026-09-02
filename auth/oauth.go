package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"golang.org/x/oauth2"
)

const oauthResponseLimit = 64 * 1024

// OAuthProfile contains only the stable identity and verified profile fields
// needed to create or link an ObjectShare account. Provider access tokens are
// deliberately never returned to callers or persisted.
type OAuthProfile struct {
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
}

// OAuthProvider implements the authorization-code flow for a configured login
// provider. Each authorization uses state plus PKCE; ObjectShare still issues
// its own JWT after the external identity has been verified.
type OAuthProvider interface {
	Key() string
	Label() string
	AuthorizationURL(state, verifier string) string
	Profile(context.Context, string, string) (*OAuthProfile, error)
}

type oauthProvider struct {
	key, label            string
	config                oauth2.Config
	profileURL, emailsURL string
	httpClient            *http.Client
}

func NewOAuthProviders(settings *config.OAuthConfig) map[string]OAuthProvider {
	providers := make(map[string]OAuthProvider)
	if settings == nil {
		return providers
	}
	if settings.Google.Enabled {
		providers["google"] = &oauthProvider{
			key: "google", label: "Google",
			config: oauth2.Config{
				ClientID: settings.Google.ClientID, ClientSecret: settings.Google.ClientSecret,
				RedirectURL: settings.PublicURL + "/oauth/google/callback",
				Scopes:      []string{"openid", "email", "profile"},
				Endpoint:    oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", AuthStyle: oauth2.AuthStyleInParams},
			},
			profileURL: "https://openidconnect.googleapis.com/v1/userinfo",
		}
	}
	if settings.GitHub.Enabled {
		providers["github"] = &oauthProvider{
			key: "github", label: "GitHub",
			config: oauth2.Config{
				ClientID: settings.GitHub.ClientID, ClientSecret: settings.GitHub.ClientSecret,
				RedirectURL: settings.PublicURL + "/oauth/github/callback",
				Scopes:      []string{"read:user", "user:email"},
				Endpoint:    oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", AuthStyle: oauth2.AuthStyleInParams},
			},
			profileURL: "https://api.github.com/user", emailsURL: "https://api.github.com/user/emails?per_page=100",
		}
	}
	return providers
}

func (provider *oauthProvider) Key() string   { return provider.key }
func (provider *oauthProvider) Label() string { return provider.label }

func (provider *oauthProvider) AuthorizationURL(state, verifier string) string {
	return provider.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

func (provider *oauthProvider) Profile(ctx context.Context, code, verifier string) (*OAuthProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	client := provider.httpClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	exchangeContext := context.WithValue(ctx, oauth2.HTTPClient, client)
	token, err := provider.config.Exchange(exchangeContext, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	if token.AccessToken == "" {
		return nil, errors.New("provider returned an empty access token")
	}
	if provider.key == "github" {
		return provider.githubProfile(ctx, client, token)
	}
	return provider.googleProfile(ctx, client, token)
}

func (provider *oauthProvider) googleProfile(ctx context.Context, client *http.Client, token *oauth2.Token) (*OAuthProfile, error) {
	var response struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := provider.getJSON(ctx, client, token, provider.profileURL, &response); err != nil {
		return nil, fmt.Errorf("load Google profile: %w", err)
	}
	return &OAuthProfile{Subject: response.Subject, Email: response.Email, EmailVerified: response.EmailVerified, DisplayName: response.Name}, nil
}

func (provider *oauthProvider) githubProfile(ctx context.Context, client *http.Client, token *oauth2.Token) (*OAuthProfile, error) {
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := provider.getJSON(ctx, client, token, provider.profileURL, &user); err != nil {
		return nil, fmt.Errorf("load GitHub profile: %w", err)
	}
	if user.ID <= 0 {
		return nil, errors.New("GitHub returned an invalid account identifier")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := provider.getJSON(ctx, client, token, provider.emailsURL, &emails); err != nil {
		return nil, fmt.Errorf("load GitHub email addresses: %w", err)
	}
	email := ""
	for _, candidate := range emails {
		if candidate.Primary && candidate.Verified {
			email = candidate.Email
			break
		}
	}
	name := strings.TrimSpace(user.Name)
	if name == "" {
		name = user.Login
	}
	return &OAuthProfile{Subject: strconv.FormatInt(user.ID, 10), Email: email, EmailVerified: email != "", DisplayName: name}, nil
}

func (provider *oauthProvider) getJSON(ctx context.Context, client *http.Client, token *oauth2.Token, endpoint string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	token.SetAuthHeader(request)
	request.Header.Set("Accept", "application/vnd.github+json, application/json")
	if provider.key == "github" {
		request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, oauthResponseLimit))
		return fmt.Errorf("provider returned %s", response.Status)
	}
	limited := &io.LimitedReader{R: response.Body, N: oauthResponseLimit + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("provider returned invalid trailing profile data")
	}
	if limited.N == 0 {
		return errors.New("provider profile response is too large")
	}
	return nil
}
