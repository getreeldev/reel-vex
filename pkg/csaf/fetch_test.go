package csaf

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// cannedRT is an http.RoundTripper that answers from memory and records that it
// was invoked. It never touches the network, so a function that bypasses the
// provided client (e.g. a regression back to bare http.Get against the .invalid
// host) fails to reach it and errors out instead.
type cannedRT struct {
	calls int
	body  string
}

func (rt *cannedRT) RoundTrip(*http.Request) (*http.Response, error) {
	rt.calls++
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(rt.body)),
		Header:     make(http.Header),
	}, nil
}

// TestDiscoverProvider_UsesProvidedClient guards S5: DiscoverProvider must fetch
// through the caller's client (which carries the timeout + retry transport), not
// a bare http.Get. The .invalid host can't resolve, so if the client were
// ignored the request would error before parsing.
func TestDiscoverProvider_UsesProvidedClient(t *testing.T) {
	rt := &cannedRT{body: `{"publisher":{"name":"ACME"},"distributions":[{"directory_url":"https://example.test/vex/"}]}`}
	client := &http.Client{Transport: rt}

	p, err := DiscoverProvider(client, "https://reel-vex.invalid/provider-metadata.json")
	if err != nil {
		t.Fatalf("DiscoverProvider: %v", err)
	}
	if rt.calls == 0 {
		t.Fatal("DiscoverProvider did not use the provided client (bare http.Get regression?)")
	}
	if p.Name != "ACME" || p.VEXFeedURL != "https://example.test/vex/" {
		t.Fatalf("parsed provider = %+v, want name=ACME url=https://example.test/vex/", p)
	}
}

// TestFetchFeedEntries_UsesProvidedClient is the same guard for the changes.csv
// fetch.
func TestFetchFeedEntries_UsesProvidedClient(t *testing.T) {
	rt := &cannedRT{body: `"2024/cve-2024-6387.json","2024-07-01T12:00:00+00:00"` + "\n"}
	client := &http.Client{Transport: rt}

	entries, err := FetchFeedEntries(client, "https://reel-vex.invalid/vex/", time.Time{})
	if err != nil {
		t.Fatalf("FetchFeedEntries: %v", err)
	}
	if rt.calls == 0 {
		t.Fatal("FetchFeedEntries did not use the provided client (bare http.Get regression?)")
	}
	if len(entries) != 1 || entries[0].Path != "2024/cve-2024-6387.json" {
		t.Fatalf("entries = %+v, want one entry for 2024/cve-2024-6387.json", entries)
	}
}
