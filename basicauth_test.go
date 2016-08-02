package basicauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoAuthGetsDenied(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not call handler")
	})

	h := New("testrealm", map[string][]string{})(next)

	w := &httptest.ResponseRecorder{}
	r, _ := http.NewRequest("GET", "/", nil)
	h.ServeHTTP(w, r)

	assertDenied(t, w)
}

func TestCorrectCredentialsGetsAllowed(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	h := New("testrealm", map[string][]string{
		"bob": {"bobspassword"},
	})(next)

	w := &httptest.ResponseRecorder{}
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("bob", "bobspassword")
	h.ServeHTTP(w, r)

	assert.Equal(t, true, called)
	assertNotDenied(t, w)
}

func TestInvalidPasswordIsDeined(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not call handler")
	})

	h := New("testrealm", map[string][]string{
		"bob": {"bobspassword"},
	})(next)

	w := &httptest.ResponseRecorder{}
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("bob", "notbobspassword")
	h.ServeHTTP(w, r)

	assertDenied(t, w)
}

func TestInvalidUserIsDenied(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not call handler")
	})

	h := New("testrealm", map[string][]string{
		"bob": {"bobspassword"},
	})(next)

	w := &httptest.ResponseRecorder{}
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("jane", "bobspassword")
	h.ServeHTTP(w, r)

	assertDenied(t, w)
}

func assertNotDenied(t *testing.T, w *httptest.ResponseRecorder) {
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func assertDenied(t *testing.T, w *httptest.ResponseRecorder) {
	assert.Equal(t, `Basic realm="testrealm"`, w.HeaderMap.Get("WWW-Authenticate"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
