package acceptance

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// fixtureContainers is every compressed file under testdata/feeds and the
// src/ content testdata/gen.go builds it from: a tarball from the files under
// src/<day>/<src> (for day 2, src/day1/<src> overlaid with src/day2/<src>,
// minus remove), a single file from src/<day>/<src>. It repeats gen.go's
// table; TestFixturesMatchSource fails when the two disagree with the files.
var fixtureContainers = []struct {
	day, src, out string
	tarball       bool
	remove        []string
}{
	{"day1", "ubuntu-vex", "security-metadata.canonical.com/vex/vex-all.tar.xz", true, nil},
	{"day2", "ubuntu-vex", "security-metadata.canonical.com/vex/vex-all.tar.xz", true, nil},
	{"day1", "rancher", "github.com/rancher/vexhub/archive/refs/heads/main.tar.gz", true, nil},
	{"day2", "rancher", "github.com/rancher/vexhub/archive/refs/heads/main.tar.gz", true,
		[]string{"vexhub-main/pkg/oci/index.docker.io/kubeovn/kube-ovn/scan.openvex.json"}},
	{"day1", "redhat-archive", "security.access.redhat.com/data/csaf/v2/vex/csaf_vex_2026-09-27.tar.zst", true, nil},
	{"day1", "oval/oval-definitions-bookworm.xml", "www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2", false, nil},
	{"day2", "oval/oval-definitions-bookworm.xml", "www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2", false, nil},
	{"day1", "oval/com.ubuntu.noble.usn.oval.xml", "security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2", false, nil},
	{"day2", "oval/com.ubuntu.noble.usn.oval.xml", "security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2", false, nil},
	{"day1", "oval/org.almalinux.alsa-9.xml", "security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2", false, nil},
	{"day1", "oval/com.oracle.elsa-ol9.xml", "linux.oracle.com/security/oval/com.oracle.elsa-ol9.xml.bz2", false, nil},
	{"day2", "oval/com.oracle.elsa-ol9.xml", "linux.oracle.com/security/oval/com.oracle.elsa-ol9.xml.bz2", false, nil},
	{"day1", "oval/com.oracle.elsa-ol8.xml", "linux.oracle.com/security/oval/com.oracle.elsa-ol8.xml.bz2", false, nil},
	{"day1", "amazon/amzn2-updateinfo.xml", "cdn.amazonlinux.com/2/core/2.0/x86_64/3fc0e1970395a5f8c19fb58cd532a97443be51797a52048a8971cd802aecec02/repodata/updateinfo.xml.gz", false, nil},
	{"day1", "amazon/al2023-updateinfo.xml", "cdn.amazonlinux.com/al2023/core/guids/5775d799f6e8c33e94d68682d3490cae250052e8798e544edd2d76501d867228/x86_64/repodata/updateinfo.xml.gz", false, nil},
}

// TestFixturesMatchSource decompresses every compressed fixture the server
// serves and compares it with the src/ content it is built from, so an edit
// to src/ that was not regenerated (or a container edited by hand) fails
// here instead of the suite testing something other than what src/ shows. It
// needs no database and runs without the integration tag.
func TestFixturesMatchSource(t *testing.T) {
	const root = "testdata"
	known := map[string]bool{}
	usedSrc := map[string]bool{}
	for _, c := range fixtureContainers {
		feed := filepath.Join(root, "feeds", c.day, filepath.FromSlash(c.out))
		known[filepath.ToSlash(feed)] = true
		raw, err := decompress(feed)
		if err != nil {
			t.Errorf("%s: %v", feed, err)
			continue
		}
		if !c.tarball {
			src := filepath.Join(root, "src", c.day, filepath.FromSlash(c.src))
			usedSrc[filepath.ToSlash(src)] = true
			want, err := os.ReadFile(src)
			if err != nil {
				t.Errorf("%s: %v", feed, err)
			} else if !bytes.Equal(raw, want) {
				t.Errorf("%s does not decompress to %s: run `go run gen.go` in testdata", feed, src)
			}
			continue
		}
		got, err := tarFiles(raw)
		if err != nil {
			t.Errorf("%s: %v", feed, err)
			continue
		}
		want, err := srcTree(root, c.day, c.src, c.remove, usedSrc)
		if err != nil {
			t.Errorf("%s: %v", feed, err)
			continue
		}
		for _, name := range sortedNames(want) {
			g, ok := got[name]
			switch {
			case !ok:
				t.Errorf("%s lacks %s", feed, name)
			case !bytes.Equal(g, want[name]):
				t.Errorf("%s: %s differs from src/: run `go run gen.go` in testdata", feed, name)
			}
		}
		for _, name := range sortedNames(got) {
			if _, ok := want[name]; !ok {
				t.Errorf("%s holds %s, which src/ does not", feed, name)
			}
		}
	}

	// Every compressed fixture is in the table, and every src/ file is in a
	// container.
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		p = filepath.ToSlash(p)
		switch {
		case strings.HasPrefix(p, "testdata/feeds/"):
			switch filepath.Ext(p) {
			case ".bz2", ".gz", ".xz", ".zst":
				if !known[p] {
					t.Errorf("%s is not in fixtureContainers", p)
				}
			}
		case strings.HasPrefix(p, "testdata/src/"):
			if !usedSrc[p] {
				t.Errorf("%s is in no container", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func decompress(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader
	switch filepath.Ext(p) {
	case ".bz2":
		r = bzip2.NewReader(f)
	case ".gz":
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		r = zr
	case ".xz":
		xr, err := xz.NewReader(f)
		if err != nil {
			return nil, err
		}
		r = xr
	case ".zst":
		zr, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	default:
		return io.ReadAll(f)
	}
	return io.ReadAll(r)
}

// tarFiles returns a tar's regular files, name -> content.
func tarFiles(raw []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[hdr.Name] = b
	}
}

// srcTree returns the files a tarball is built from, path -> content, and
// marks each src/ file it reads in used.
func srcTree(root, day, src string, remove []string, used map[string]bool) (map[string][]byte, error) {
	files := map[string][]byte{}
	layers := []string{filepath.Join(root, "src", "day1", src)}
	if day == "day2" {
		layers = append(layers, filepath.Join(root, "src", "day2", src))
	}
	for _, layer := range layers {
		err := filepath.WalkDir(layer, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(layer, p)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			files[filepath.ToSlash(rel)] = b
			used[filepath.ToSlash(p)] = true
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	for _, r := range remove {
		delete(files, r)
	}
	return files, nil
}

func sortedNames(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
