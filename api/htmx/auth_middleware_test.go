package htmx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AutisticShark/ObjectShare/db"
)

// serveAuthenticated runs request through Authenticate and reports the
// identity, if any, that reached the next handler.
func serveAuthenticated(handler *Handler, request *http.Request) (*httptest.ResponseRecorder, *identity, bool) {
	var served *identity
	reached := false
	response := httptest.NewRecorder()
	handler.Authenticate(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		reached, served = true, currentIdentity(request)
		writer.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)
	return response, served, reached
}

// A reverse proxy protected with HTTP Basic authentication forwards its own
// Authorization header; that must not hide the ObjectShare JWT cookie.
func TestNonBearerAuthorizationFallsBackToJWTCookie(t *testing.T) {
	repository := newAuthMemoryRepository()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "user@example.com", DisplayName: "User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	token, _ := issueTestJWT(t, handler, user)
	for _, authorization := range []string{"Basic dXNlcjpwYXNz", `Digest username="user", realm="proxy"`, "Negotiate abc", "Bearertoken"} {
		request := httptest.NewRequest(http.MethodGet, "/account", nil)
		request.Header.Set("Authorization", authorization)
		request.AddCookie(&http.Cookie{Name: handler.jwtCookieName(), Value: token})
		response, served, _ := serveAuthenticated(handler, request)
		if served == nil || served.User.ID != user.ID || served.Transport != transportCookie {
			t.Fatalf("Authorization %q hid the JWT cookie: identity=%v", authorization, served)
		}
		if len(response.Result().Cookies()) != 0 {
			t.Fatalf("Authorization %q cleared a valid JWT cookie", authorization)
		}

		anonymous := httptest.NewRequest(http.MethodGet, "/", nil)
		anonymous.Header.Set("Authorization", authorization)
		if response, served, reached := serveAuthenticated(handler, anonymous); !reached || served != nil || response.Code != http.StatusNoContent {
			t.Fatalf("Authorization %q without a cookie: reached=%v identity=%v status=%d", authorization, reached, served, response.Code)
		}
	}
}
