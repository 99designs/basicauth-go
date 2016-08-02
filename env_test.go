package basicauth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvLoading(t *testing.T) {
	os.Setenv("TESTAPI_BOB", "bobspassword")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	h := NewFromEnv("testrealm", "TESTAPI_")(next)

	w := &httptest.ResponseRecorder{}
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("bob", "bobspassword")
	h.ServeHTTP(w, r)

	assert.Equal(t, true, called)
	assertNotDenied(t, w)
}
