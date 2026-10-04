//go:build integration

// Package acceptance runs real vendor documents through every adapter,
// ingest, Postgres and the HTTP API, and checks each answer against what the
// vendor document says. The fixtures under testdata are trimmed copies of the
// live feeds (see testdata/README.md); a local HTTP server serves them at
// paths shaped like the vendors' URLs, the server binary ingests them into a
// database of its own, and the cases in cases_*_test.go query it.
//
// It needs REEL_VEX_TEST_PG_DSN (any database on the server: the suite creates
// and drops its own, so it can run beside test/integration). Without it the
// suite is skipped, except under CI=true, where a missing database fails it.
package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// env is the running system under test, set up once by TestMain.
var env struct {
	binPath, configPath, dsn, workDir string
	serverURL                         string
	feeds                             *feedServer
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

// run does setup, m.Run and teardown so deferred cleanup runs before os.Exit.
func run(m *testing.M) int {
	adminDSN := os.Getenv("REEL_VEX_TEST_PG_DSN")
	if adminDSN == "" {
		if os.Getenv("CI") == "true" {
			fmt.Fprintln(os.Stderr, "REEL_VEX_TEST_PG_DSN not set under CI=true: the acceptance suite needs a database")
			return 1
		}
		// The tests that need no database still run; TestAcceptance skips.
		fmt.Fprintln(os.Stderr, "REEL_VEX_TEST_PG_DSN not set; skipping the acceptance cases")
		return m.Run()
	}
	start := time.Now()
	fail := func(format string, args ...any) int {
		fmt.Fprintf(os.Stderr, "acceptance setup: "+format+"\n", args...)
		return 1
	}

	dir, err := os.MkdirTemp(os.TempDir(), "reel-vex-acceptance-")
	if err != nil {
		return fail("temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	env.workDir = dir

	dsn, drop, err := createDatabase(adminDSN)
	if err != nil {
		return fail("create database: %v", err)
	}
	defer drop()
	env.dsn = dsn

	env.binPath = filepath.Join(dir, "reel-vex")
	build := exec.Command("go", "build", "-o", env.binPath, "./cmd/server")
	build.Dir = repoRoot()
	if out, err := build.CombinedOutput(); err != nil {
		return fail("build: %v\n%s", err, out)
	}

	env.feeds, err = newFeedServer(filepath.Join(repoRoot(), "test", "acceptance", "testdata", "feeds"))
	if err != nil {
		return fail("feed server: %v", err)
	}
	defer env.feeds.Close()

	env.configPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(env.configPath, []byte(config(env.feeds.URL())), 0o644); err != nil {
		return fail("write config: %v", err)
	}

	if err := ingest("day1", day1Want); err != nil {
		return fail("%v", err)
	}

	port, err := freePort()
	if err != nil {
		return fail("free port: %v", err)
	}
	env.serverURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	var serveLog syncBuffer
	serve := exec.Command(env.binPath,
		"-db", env.dsn,
		"-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-config", env.configPath,
		"-ingest-interval", "999h",
		"serve",
	)
	serve.Env = childEnv()
	serve.Stdout = &serveLog
	serve.Stderr = &serveLog
	serve.WaitDelay = 3 * time.Second
	if err := serve.Start(); err != nil {
		return fail("start server: %v", err)
	}
	stopServe := func() {
		serve.Process.Kill()
		serve.Wait()
	}
	defer stopServe()
	if err := waitHealthy(env.serverURL+"/healthz", 15*time.Second); err != nil {
		return fail("server not ready: %v\n%s", err, serveLog.String())
	}
	// The ingest above is fresh, so the scheduler must skip its boot run; an
	// ingest racing the cases would make every answer timing-dependent.
	if err := waitFor(func() bool { return strings.Contains(serveLog.String(), "boot ingest skipped") }, 5*time.Second); err != nil {
		return fail("server did not skip its boot ingest:\n%s", serveLog.String())
	}

	fmt.Fprintf(os.Stderr, "acceptance setup ready in %s\n", time.Since(start).Round(time.Millisecond))
	code := m.Run()
	// Every case answered; the server must not have warned about any of them.
	stopServe()
	if bad := warnings(serveLog.String(), nil); len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "acceptance: the server logged:\n  %s\n", strings.Join(bad, "\n  "))
		return 1
	}
	return code
}

// childEnv is the environment of the server binary the suite runs: every
// proxy variable points at a closed port, so a regression that reached for a
// live vendor URL instead of the configured one fails instead of reaching the
// network. Go never proxies a loopback address, so the fixture server is
// still reached directly.
func childEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY":
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY=")
}

// adapters is every adapter type in config.yaml, one entry per fixture feed;
// the ids are the production ids. Each line is "type id path", path relative
// to the fixture server and shaped like the vendor's URL (the adapters read
// releases from it).
var adapters = []string{
	"csaf redhat security.access.redhat.com/data/csaf/v2/provider-metadata.json",
	"csaf suse www.suse.com/.well-known/csaf/provider-metadata.json",
	"ubuntu-vex ubuntu-vex security-metadata.canonical.com/vex/vex-all.tar.xz",
	"ubuntu-oval ubuntu-oval-noble security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2",
	"debian-oval debian-oval-bookworm www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2",
	"rancher-vex rancher-vex github.com/rancher/vexhub/archive/refs/heads/main.tar.gz",
	"alpine-secdb alpine-secdb-v3.22-main secdb.alpinelinux.org/v3.22/main.json",
	"alpine-secdb alpine-secdb-v3.22-community secdb.alpinelinux.org/v3.22/community.json",
	"amazon-alas amazon-alas-2 cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
	"amazon-alas amazon-alas-2023 cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
	"almalinux-oval almalinux-oval-9 security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2",
	"oracle-oval oracle-oval-ol9 linux.oracle.com/security/oval/com.oracle.elsa-ol9.xml.bz2",
	"oracle-oval oracle-oval-ol8 linux.oracle.com/security/oval/com.oracle.elsa-ol8.xml.bz2",
}

func config(base string) string {
	var b strings.Builder
	b.WriteString("adapters:\n")
	for _, a := range adapters {
		f := strings.Fields(a)
		fmt.Fprintf(&b, "  - type: %s\n    id: %s\n    url: %s/%s\n", f[0], f[1], base, f[2])
	}
	fmt.Fprintf(&b, "aliases:\n  - type: redhat-repository-to-cpe\n    id: redhat\n    url: %s/security.access.redhat.com/data/metrics/repository-to-cpe.json\n", base)
	return b.String()
}

// logLine matches the default slog text handler's level field.
var logLine = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d (DEBUG|INFO|WARN|ERROR) (.*)$`)

// ingestWant is what one day's ingest must do beyond logging "adapter done"
// for every adapter and the alias fetcher.
type ingestWant struct {
	// firstRun: every adapter reports complete=true and processed>0, since
	// each reads its whole feed for the first time.
	firstRun bool
	// warn are the WARN lines the ingest must log, each exactly once, each
	// given as the substrings it contains; any other WARN or ERROR fails.
	warn [][]string
	// info are further lines the ingest must log, each at least once.
	info [][]string
	// rows is the number of statements rows each adapter owns afterwards.
	rows map[string]int
}

// day1Want: the Red Hat cold start reads its two oldest documents from the
// bulk archive (the feed serves no loose copy of them, so a cold start that
// skipped the archive would 404 on them).
var day1Want = ingestWant{
	firstRun: true,
	info:     [][]string{{"INFO csaf bulk archive: done ", "adapter=redhat ", "docs=2 "}},
	rows: map[string]int{
		"redhat": 85, "suse": 257, "ubuntu-vex": 370, "ubuntu-oval-noble": 11,
		"debian-oval-bookworm": 8, "rancher-vex": 8,
		"alpine-secdb-v3.22-main": 70, "alpine-secdb-v3.22-community": 8,
		"amazon-alas-2": 2, "amazon-alas-2023": 3, "almalinux-oval-9": 4,
		"oracle-oval-ol9": 44, "oracle-oval-ol8": 3,
	},
}

// day2Want: the Alpine community feed loses more than 20% of its rows, so its
// sweep is refused, and SUSE's index.txt loses more than 20% of its CVEs, so
// its withdrawal is.
var day2Want = ingestWant{
	warn: [][]string{
		{" WARN sweep ", "adapter=alpine-secdb-v3.22-community ", "refused="},
		{" WARN withdraw ", "adapter=suse ", "refused="},
	},
	// Day 1's, less every removal the day-2 cases describe: Red Hat 9 (a
	// product dropped from a re-published document, a document re-published
	// empty, a withdrawn CVE), Ubuntu OpenVEX 7 (a dropped statement; the
	// changed verdict's 7 rows are replaced), Debian, Alpine main and Rancher
	// 1 each, Oracle ol9 the 6 rows of the dropped ELSA; the two refused
	// removals keep every row.
	rows: map[string]int{
		"redhat": 76, "suse": 257, "ubuntu-vex": 363, "ubuntu-oval-noble": 11,
		"debian-oval-bookworm": 7, "rancher-vex": 7,
		"alpine-secdb-v3.22-main": 69, "alpine-secdb-v3.22-community": 8,
		"amazon-alas-2": 2, "amazon-alas-2023": 3, "almalinux-oval-9": 4,
		"oracle-oval-ol9": 38, "oracle-oval-ol8": 3,
	},
}

// ingest runs the binary's ingest subcommand against the fixtures of one day
// and fails on anything want does not expect: a WARN or ERROR line, an
// adapter that did not finish, a fixture no adapter asked for or a path the
// fixture server does not have, rows owned in other numbers. A fixture an
// adapter could not read would otherwise show up only as a confusing wrong
// answer much later.
func ingest(day string, want ingestWant) error {
	env.feeds.SetDay(day)
	cmd := exec.Command(env.binPath, "-db", env.dsn, "-config", env.configPath, "ingest")
	cmd.Env = childEnv()
	out, err := cmd.CombinedOutput()
	logPath := filepath.Join(env.workDir, "ingest-"+day+".log")
	os.WriteFile(logPath, out, 0o644)
	if err != nil {
		return fmt.Errorf("ingest %s: %v\n%s", day, err, out)
	}
	bad := warnings(string(out), want.warn)
	done := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		m := logLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if strings.HasPrefix(m[2], "adapter done ") {
			fields := map[string]string{}
			for _, f := range strings.Fields(m[2]) {
				if k, v, ok := strings.Cut(f, "="); ok {
					fields[k] = v
				}
			}
			id := fields["adapter"]
			done[id] = true
			if want.firstRun && (fields["complete"] != "true" || fields["processed"] == "0") {
				bad = append(bad, "adapter "+id+" did not read its whole feed on its first run: "+m[2])
			}
		}
		if strings.HasPrefix(m[2], "alias fetch ") {
			done["alias:redhat"] = true
		}
	}
	for _, a := range adapters {
		if id := strings.Fields(a)[1]; !done[id] {
			bad = append(bad, "adapter "+id+" never logged \"adapter done\"")
		}
	}
	if !done["alias:redhat"] {
		bad = append(bad, "the redhat-repository-to-cpe alias never logged \"alias fetch\"")
	}
	for _, sub := range want.info {
		if countLines(string(out), sub) == 0 {
			bad = append(bad, fmt.Sprintf("no line containing %q", sub))
		}
	}
	bad = append(bad, env.feeds.check()...)
	got, err := rowsByAdapter()
	if err != nil {
		bad = append(bad, "count rows: "+err.Error())
	}
	bad = append(bad, diff(mapLines(got), mapLines(want.rows), func(s string) string { return s })...)
	if len(bad) > 0 {
		return fmt.Errorf("ingest %s reported problems:\n  %s\nfull log:\n%s", day, strings.Join(bad, "\n  "), out)
	}
	return nil
}

// warnings returns every WARN and ERROR line of log that no entry of expected
// matches, and a complaint for every entry not matched exactly once.
func warnings(log string, expected [][]string) []string {
	var bad []string
	seen := make([]int, len(expected))
	for _, line := range strings.Split(log, "\n") {
		m := logLine.FindStringSubmatch(line)
		if m == nil || (m[1] != "WARN" && m[1] != "ERROR") {
			continue
		}
		matched := false
		for i, sub := range expected {
			if containsAll(line, sub) {
				seen[i]++
				matched = true
			}
		}
		if !matched {
			bad = append(bad, line)
		}
	}
	for i, sub := range expected {
		if seen[i] != 1 {
			bad = append(bad, fmt.Sprintf("%d lines containing %q, want exactly 1", seen[i], sub))
		}
	}
	return bad
}

func countLines(log string, sub []string) int {
	n := 0
	for _, line := range strings.Split(log, "\n") {
		if containsAll(line, sub) {
			n++
		}
	}
	return n
}

func containsAll(s string, sub []string) bool {
	for _, x := range sub {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

// rowsByAdapter counts the statements rows each adapter owns.
func rowsByAdapter() (map[string]int, error) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.dsn)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, `SELECT coalesce(adapter_id, ''), count(*) FROM statements GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	got := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		got[id] = n
	}
	return got, rows.Err()
}

// mapLines renders a row count map as "adapter rows=N" lines for diff.
func mapLines(m map[string]int) []string {
	var out []string
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s rows=%d", k, v))
	}
	return out
}

// createDatabase creates a database with a random name on the server adminDSN
// points at, and returns its DSN and a function that drops it.
func createDatabase(adminDSN string) (string, func(), error) {
	ctx := context.Background()
	u, err := url.Parse(adminDSN)
	if err != nil {
		return "", nil, err
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return "", nil, err
	}
	name := "reel_vex_acceptance_" + hex.EncodeToString(suffix)
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return "", nil, err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		return "", nil, err
	}
	drop := func() {
		c, err := pgx.Connect(ctx, adminDSN)
		if err != nil {
			fmt.Fprintf(os.Stderr, "drop database %s: %v\n", name, err)
			return
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			fmt.Fprintf(os.Stderr, "drop database %s: %v\n", name, err)
		}
	}
	u.Path = "/" + name
	return u.String(), drop, nil
}

// syncBuffer is a bytes.Buffer safe for the child's output copier and a reader.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func repoRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("go.mod not found")
		}
		dir = parent
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitHealthy(u string, timeout time.Duration) error {
	return waitFor(func() bool {
		resp, err := http.Get(u)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, timeout)
}

func waitFor(cond func() bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s", timeout)
}
