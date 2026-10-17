package audiobookshelf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// The shape GET /api/users returns to an admin key in ABS v2.37.1
// (UserController.findAll -> toOldJSONForBrowser(hideRootToken, true)).
const usersResponseWithTokens = `{"users":[
 {"id":"u-1","username":"Alice","email":"a@example.invalid","type":"user","token":"legacy-token-alice",
  "isOldToken":false,"isActive":true,"isLocked":false,"lastSeen":null,"createdAt":1,
  "permissions":{"download":true},"librariesAccessible":[],"itemTagsSelected":[],"hasOpenIDLink":true},
 {"id":"u-2","username":"bob","type":"user","token":"legacy-token-bob","isActive":false,"hasOpenIDLink":false}
]}`

func TestListUsersDecodesOnlySummaryFields(t *testing.T) {
	var gotAuth, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(usersResponseWithTokens))
	}))
	defer server.Close()

	users, err := NewClient(server.URL, "admin-key").ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if gotPath != "/api/users" || gotAuth != "Bearer admin-key" {
		t.Fatalf("request = %q with %q, want /api/users with the admin key", gotPath, gotAuth)
	}
	want := []UserSummary{
		{ID: "u-1", Username: "Alice", HasOpenIDLink: true, IsActive: true},
		{ID: "u-2", Username: "bob", HasOpenIDLink: false, IsActive: false},
	}
	if !reflect.DeepEqual(users, want) {
		t.Fatalf("users = %+v, want %+v", users, want)
	}

	// Nothing booksync holds may carry a member's legacy token.
	encoded, err := json.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "legacy-token") {
		t.Fatalf("decoded users still carry a token: %s", encoded)
	}
	if _, ok := reflect.TypeOf(UserSummary{}).FieldByName("Token"); ok {
		t.Fatal("UserSummary must not have a Token field")
	}
}

func TestListUsersRefusesNonOKWithoutBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`secret-looking-body`))
	}))
	defer server.Close()

	_, err := NewClient(server.URL, "not-admin").ListUsers(context.Background())
	if err == nil {
		t.Fatal("expected an error for 403")
	}
	if strings.Contains(err.Error(), "secret-looking-body") {
		t.Fatalf("error leaks the response body: %v", err)
	}
}

func TestListUsersRefusesMissingList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"something":"else"}`))
	}))
	defer server.Close()

	if _, err := NewClient(server.URL, "admin-key").ListUsers(context.Background()); err == nil {
		t.Fatal("expected an error when the response has no users list")
	}
}
