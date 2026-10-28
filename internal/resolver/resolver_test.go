package resolver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveRepoURL_NPM(t *testing.T) {
	// Mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/@test/pkg" {
			fmt.Fprintln(w, `{"repository": {"url": "git+https://github.com/test/pkg.git"}}`)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	// Override base URL and client for test
	oldBase := npmRegistryBase
	npmRegistryBase = ts.URL + "/"
	restoreClient := SetHTTPClient(ts.Client())
	defer func() {
		npmRegistryBase = oldBase
		restoreClient()
	}()

	// Test
	url, err := ResolveRepoURL("pkg:npm/@test/pkg@1.0.0")
	if err != nil {
		t.Fatalf("ResolveRepoURL failed: %v", err)
	}

	expected := "github.com/test/pkg"
	if url != expected {
		t.Errorf("expected %q, got %q", expected, url)
	}
}
