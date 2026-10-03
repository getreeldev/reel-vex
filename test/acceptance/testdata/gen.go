//go:build ignore

// gen rebuilds every compressed container the acceptance fixture server
// serves (tar.xz, tar.gz, tar.zst, bz2, gz) from the trimmed, uncompressed
// vendor content under src/. Run it from this directory:
//
//	go run gen.go
//
// Output is byte-for-byte reproducible: fixed tar headers, no gzip name or
// time, single-threaded zstd. bzip2 has no encoder in the Go standard library,
// so bz2 files are written by the bzip2 command, which must be on PATH.
//
// day2 containers are the day1 entries overlaid with src/day2 (and minus the
// entries listed in remove), so a day-2 edit is visible as one small file.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

var (
	day1Time = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	day2Time = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
)

// rancherCommit is the commit GitHub recorded in the downloaded snapshot's pax
// global header; the adapter logs it.
const rancherCommit = "14ccc8f1ff2cadd0c12f351244f801cbb1e9801d"

func main() {
	type tarball struct {
		src, out, format string
		dirs             bool   // emit directory entries, as the vendor archive does
		global           string // pax global header comment
		remove           []string
	}
	tarballs := []struct {
		day string
		tarball
	}{
		{"day1", tarball{"ubuntu-vex", "security-metadata.canonical.com/vex/vex-all.tar.xz", "xz", true, "", nil}},
		{"day2", tarball{"ubuntu-vex", "security-metadata.canonical.com/vex/vex-all.tar.xz", "xz", true, "", nil}},
		{"day1", tarball{"rancher", "github.com/rancher/vexhub/archive/refs/heads/main.tar.gz", "gz", true, rancherCommit, nil}},
		{"day2", tarball{"rancher", "github.com/rancher/vexhub/archive/refs/heads/main.tar.gz", "gz", true, rancherCommit,
			[]string{"vexhub-main/pkg/oci/index.docker.io/kubeovn/kube-ovn/scan.openvex.json"}}},
		{"day1", tarball{"redhat-archive", "security.access.redhat.com/data/csaf/v2/vex/csaf_vex_2026-09-27.tar.zst", "zst", false, "", nil}},
	}
	for _, t := range tarballs {
		entries, err := tarEntries(t.day, t.src, t.remove)
		check(err)
		mod := day1Time
		if t.day == "day2" {
			mod = day2Time
		}
		raw, err := buildTar(entries, t.dirs, t.global, mod)
		check(err)
		write(filepath.Join("feeds", t.day, t.out), compress(t.format, raw))
	}

	files := []struct{ day, src, out, format string }{
		{"day1", "oval/oval-definitions-bookworm.xml", "www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2", "bz2"},
		{"day2", "oval/oval-definitions-bookworm.xml", "www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2", "bz2"},
		{"day1", "oval/com.ubuntu.noble.usn.oval.xml", "security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2", "bz2"},
		{"day2", "oval/com.ubuntu.noble.usn.oval.xml", "security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2", "bz2"},
		{"day1", "oval/org.almalinux.alsa-9.xml", "security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2", "bz2"},
		{"day1", "oval/com.oracle.elsa-ol9.xml", "linux.oracle.com/security/oval/com.oracle.elsa-ol9.xml.bz2", "bz2"},
		{"day2", "oval/com.oracle.elsa-ol9.xml", "linux.oracle.com/security/oval/com.oracle.elsa-ol9.xml.bz2", "bz2"},
		{"day1", "oval/com.oracle.elsa-ol8.xml", "linux.oracle.com/security/oval/com.oracle.elsa-ol8.xml.bz2", "bz2"},
		{"day1", "amazon/amzn2-updateinfo.xml", "cdn.amazonlinux.com/2/core/2.0/x86_64/3fc0e1970395a5f8c19fb58cd532a97443be51797a52048a8971cd802aecec02/repodata/updateinfo.xml.gz", "gz"},
		{"day1", "amazon/al2023-updateinfo.xml", "cdn.amazonlinux.com/al2023/core/guids/5775d799f6e8c33e94d68682d3490cae250052e8798e544edd2d76501d867228/x86_64/repodata/updateinfo.xml.gz", "gz"},
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join("src", f.day, f.src))
		check(err)
		write(filepath.Join("feeds", f.day, f.out), compress(f.format, b))
	}
}

// tarEntries returns the archive's files, path -> content: src/day1/<src>,
// and for day2 overlaid with src/day2/<src> and minus remove.
func tarEntries(day, src string, remove []string) (map[string][]byte, error) {
	entries := map[string][]byte{}
	layers := []string{filepath.Join("src", "day1", src)}
	if day == "day2" {
		layers = append(layers, filepath.Join("src", "day2", src))
	}
	for _, root := range layers {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			entries[filepath.ToSlash(rel)] = b
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	for _, r := range remove {
		if _, ok := entries[r]; !ok {
			return nil, fmt.Errorf("remove %s: not in %s", r, src)
		}
		delete(entries, r)
	}
	return entries, nil
}

func buildTar(entries map[string][]byte, dirs bool, global string, mod time.Time) ([]byte, error) {
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if global != "" {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header",
			PAXRecords: map[string]string{"comment": global}, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
	}
	written := map[string]bool{}
	for _, n := range names {
		if dirs {
			parts := strings.Split(path.Dir(n), "/")
			for i := range parts {
				d := strings.Join(parts[:i+1], "/") + "/"
				if d == "./" || written[d] {
					continue
				}
				written[d] = true
				if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d, Mode: 0o755, ModTime: mod}); err != nil {
					return nil, err
				}
			}
		}
		b := entries[n]
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(b)), ModTime: mod}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func compress(format string, b []byte) []byte {
	var buf bytes.Buffer
	switch format {
	case "xz":
		w, err := xz.NewWriter(&buf)
		check(err)
		_, err = w.Write(b)
		check(err)
		check(w.Close())
	case "gz":
		w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		check(err)
		_, err = w.Write(b)
		check(err)
		check(w.Close())
	case "zst":
		w, err := zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1))
		check(err)
		_, err = w.Write(b)
		check(err)
		check(w.Close())
	case "bz2":
		cmd := exec.Command("bzip2", "-9", "-c")
		cmd.Stdin = bytes.NewReader(b)
		cmd.Stdout = &buf
		cmd.Stderr = os.Stderr
		check(cmd.Run())
	default:
		panic("unknown format " + format)
	}
	return buf.Bytes()
}

func write(p string, b []byte) {
	check(os.MkdirAll(filepath.Dir(p), 0o755))
	check(os.WriteFile(p, b, 0o644))
	fmt.Printf("%8d %s\n", len(b), p)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
