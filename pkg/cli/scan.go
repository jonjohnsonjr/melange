// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	apko_log "chainguard.dev/apko/pkg/log"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"github.com/klauspost/compress/gzip"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
)

func Scan() *cobra.Command {
	var (
		keys []string
		repo []string
	)

	cmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan an existing APK to generate .PKGINFO",
		Example: `melange scan < foo.apk`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ScanCmd(cmd.Context(), args[0], repo[0])
		},
	}

	cmd.Flags().StringSliceVarP(&keys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&repo, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")

	return cmd
}

func ScanCmd(ctx context.Context, file string, repo string) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "ScanCmd")
	defer span.End()

	// TODO: Flags, probably.
	archs := []string{"aarch64"}

	for _, arch := range archs {
		// TODO: Also handle subpackages.
		cfg, err := config.ParseConfiguration(file)
		if err != nil {
			return fmt.Errorf("parse config: %w", err)
		}

		pkgConfig := cfg.Package

		u := fmt.Sprintf("%s/%s/%s-%s-r%d.apk", repo, arch, pkgConfig.Name, pkgConfig.Version, pkgConfig.Epoch)
		resp, err := http.Get(u)
		if err != nil {
			return fmt.Errorf("get %s: %w", u, err)
		}
		zr, err := gzip.NewReader(bufio.NewReaderSize(resp.Body, 1<<20))
		if err != nil {
			return fmt.Errorf("gzip %q: %w", u, err)
		}
		tr := tar.NewReader(zr)

		info, b, err := findPkgInfo(tr)
		if err != nil {
			return fmt.Errorf("findPkgInfo: %w", err)
		}

		// TODO: Is this right?
		pkgConfig.Commit = info.commit

		pkg, err := build.NewPackageContext(&pkgConfig)
		if err != nil {
			return err
		}

		installedSize, err := strconv.ParseInt(info.size, 10, 64)
		if err != nil {
			return err
		}

		logger := &apko_log.Adapter{
			Out:   io.Discard,
			Level: apko_log.InfoLevel,
		}

		dir, err := os.MkdirTemp("", info.pkgname)
		if err != nil {
			return fmt.Errorf("mkdirtemp: %w", err)
		}
		defer os.RemoveAll(dir)

		logger.Printf("dir: %s", dir)

		bb := &build.Build{
			WorkspaceDir:    dir,
			SourceDateEpoch: time.Unix(0, 0),
			Configuration:   *cfg,
		}

		pb := build.PackageBuild{
			Build:         bb,
			Origin:        pkg,
			PackageName:   pkg.Package.Name,
			OriginName:    pkg.Package.Name,
			Dependencies:  pkg.Package.Dependencies,
			Options:       pkg.Package.Options,
			Scriptlets:    pkg.Package.Scriptlets,
			Description:   pkg.Package.Description,
			URL:           pkg.Package.URL,
			Commit:        pkg.Package.Commit,
			InstalledSize: installedSize,
			DataHash:      info.datahash,
			Arch:          info.arch,
			Logger:        logger,
		}

		if info.builddate != "" {
			sec, err := strconv.ParseInt(info.builddate, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as timestamp: %w", info.builddate, err)
			}
			pb.Build.SourceDateEpoch = time.Unix(sec, 0)
		}

		subdir := pb.WorkspaceSubdir()
		if err := os.MkdirAll(subdir, 0o755); err != nil {
			return fmt.Errorf("unable to ensure workspace exists: %w", err)
		}

		if err := writeToDir(subdir, tr); err != nil {
			return fmt.Errorf("writeToDir: %w", err)
		}

		subpkgs := map[string]build.PackageBuild{}
		controls := map[string][]byte{}

		for _, subpkg := range cfg.Subpackages {
			logger.Printf("subpackage %q", subpkg.Name)
			logger.Printf("pcbcpn: %q", bb.Configuration.Package.Name)
			subpkgConfig := subpkg

			u := fmt.Sprintf("%s/%s/%s-%s-r%d.apk", repo, arch, subpkgConfig.Name, pkgConfig.Version, pkgConfig.Epoch)
			resp, err := http.Get(u)
			if err != nil {
				return fmt.Errorf("get %s: %w", u, err)
			}
			if resp.StatusCode != http.StatusOK {
				log.Printf("Get %s: %d", u, resp.StatusCode)
				continue
			}

			zr, err := gzip.NewReader(bufio.NewReaderSize(resp.Body, 1<<20))
			if err != nil {
				return fmt.Errorf("gzip %q: %w", u, err)
			}
			tr := tar.NewReader(zr)

			info, b, err := findPkgInfo(tr)
			if err != nil {
				return fmt.Errorf("findPkgInfo: %w", err)
			}

			controls[subpkgConfig.Name] = b

			// TODO: Is this right?
			subpkgConfig.Commit = info.commit

			subpkg, err := build.NewSubpackageContext(&subpkgConfig)
			if err != nil {
				return err
			}

			installedSize, err := strconv.ParseInt(info.size, 10, 64)
			if err != nil {
				return err
			}

			logger := &apko_log.Adapter{
				Out:   io.Discard,
				Level: apko_log.InfoLevel,
			}

			pb := build.PackageBuild{
				Build:         bb,
				Origin:        pkg,
				PackageName:   subpkg.Subpackage.Name,
				OriginName:    pkg.Package.Name,
				Dependencies:  subpkg.Subpackage.Dependencies,
				Options:       subpkg.Subpackage.Options,
				Scriptlets:    subpkg.Subpackage.Scriptlets,
				Description:   subpkg.Subpackage.Description,
				URL:           subpkg.Subpackage.URL,
				Commit:        subpkg.Subpackage.Commit,
				InstalledSize: installedSize,
				DataHash:      info.datahash,
				Arch:          info.arch,
				Logger:        logger,
			}

			subpkgs[subpkgConfig.Name] = pb

			if info.builddate != "" {
				sec, err := strconv.ParseInt(info.builddate, 10, 64)
				if err != nil {
					return fmt.Errorf("parsing %q as timestamp: %w", info.builddate, err)
				}
				pb.Build.SourceDateEpoch = time.Unix(sec, 0)
			}

			subdir := pb.WorkspaceSubdir()
			if err := os.MkdirAll(subdir, 0o755); err != nil {
				return fmt.Errorf("unable to ensure workspace exists: %w", err)
			}

			if err := writeToDir(subdir, tr); err != nil {
				return fmt.Errorf("writeToDir: %w", err)
			}
		}

		for _, subpkg := range cfg.Subpackages {
			pb := subpkgs[subpkg.Name]
			b := controls[subpkg.Name]

			if err := pb.GenerateDependencies(); err != nil {
				return err
			}

			var buf bytes.Buffer
			if err := pb.GenerateControlData(&buf); err != nil {
				return fmt.Errorf("unable to process control template: %w", err)
			}

			generated := buf.Bytes()

			old := fmt.Sprintf("%s-%s.apk", info.pkgname, info.pkgver)
			diff := Diff(old, b, file, generated)
			if diff != nil {
				if _, err := os.Stdout.Write(diff); err != nil {
					return fmt.Errorf("write: %w", err)
				}
			}
		}

		if err := pb.GenerateDependencies(); err != nil {
			return err
		}

		var buf bytes.Buffer
		if err := pb.GenerateControlData(&buf); err != nil {
			return fmt.Errorf("unable to process control template: %w", err)
		}

		generated := buf.Bytes()

		old := fmt.Sprintf("%s-%s.apk", info.pkgname, info.pkgver)
		diff := Diff(old, b, file, generated)
		if diff != nil {
			if _, err := os.Stdout.Write(diff); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}

	}

	return nil
}

type pkginfo struct {
	pkgname   string
	pkgver    string
	size      string
	arch      string
	origin    string
	pkgdesc   string
	url       string
	commit    string
	builddate string
	license   string
	triggers  string
	datahash  string
}

func findPkgInfo(tr *tar.Reader) (*pkginfo, []byte, error) {
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if hdr.Name == ".PKGINFO" {
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("readall: %w", err)
			}
			info, err := parsePkgInfo(bytes.NewReader(b))
			if err != nil {
				return nil, nil, fmt.Errorf("parsePkgInfo: %w", err)
			}

			return info, b, err
		}
	}

	return nil, nil, fmt.Errorf("did not find it")
}

// TODO: import "gopkg.in/ini.v1"
func parsePkgInfo(in io.Reader) (*pkginfo, error) {
	scanner := bufio.NewScanner(in)

	pkg := pkginfo{}

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		before = strings.TrimSpace(before)
		after = strings.TrimSpace(after)

		switch before {
		case "pkgname":
			pkg.pkgname = after
		case "pkgver":
			pkg.pkgver = after
		case "arch":
			pkg.arch = after
		case "size":
			pkg.size = after
		case "origin":
			pkg.origin = after
		case "pkgdesc":
			pkg.pkgdesc = after
		case "url":
			pkg.url = after
		case "commit":
			pkg.commit = after
		case "builddate":
			pkg.builddate = after
		case "license":
			pkg.license = after
		case "triggers":
			pkg.triggers = after
		case "datahash":
			pkg.datahash = after
		}
	}

	return &pkg, scanner.Err()
}

func versionEpoch(in string) (string, uint64) {
	last := strings.LastIndex(in, "-r")
	if last == -1 {
		panic(in)
	}

	ver := in[:last]

	epoch, err := strconv.ParseUint(in[last+2:], 10, 64)
	if err != nil {
		panic(err)
	}

	return ver, epoch
}

func writeToDir(dst string, tr *tar.Reader) error {
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(dst, header.Name)

		switch header.Typeflag {

		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}

		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeLink:
			src := filepath.Join(dst, header.Linkname)
			if err := os.Link(src, target); err != nil {
				return fmt.Errorf("linking: %w", err)
			}
		case tar.TypeSymlink:
			src := filepath.Join(dst, header.Linkname)

			// Case sensitivity is stupid.
			if extant, err := os.Readlink(target); err == nil && extant == src {
				continue
			}

			if err := os.Symlink(src, target); err != nil {
				return fmt.Errorf("symlinking: %w", err)
			}
		default:
			return fmt.Errorf("unhandled tar typeflag: %v", header.Typeflag)
		}
	}

	return nil
}

// From src/internal/diff/diff.go

// A pair is a pair of values tracked for both the x and y side of a diff.
// It is typically a pair of line indexes.
type pair struct{ x, y int }

// Diff returns an anchored diff of the two texts old and new
// in the “unified diff” format. If old and new are identical,
// Diff returns a nil slice (no output).
//
// Unix diff implementations typically look for a diff with
// the smallest number of lines inserted and removed,
// which can in the worst case take time quadratic in the
// number of lines in the texts. As a result, many implementations
// either can be made to run for a long time or cut off the search
// after a predetermined amount of work.
//
// In contrast, this implementation looks for a diff with the
// smallest number of “unique” lines inserted and removed,
// where unique means a line that appears just once in both old and new.
// We call this an “anchored diff” because the unique lines anchor
// the chosen matching regions. An anchored diff is usually clearer
// than a standard diff, because the algorithm does not try to
// reuse unrelated blank lines or closing braces.
// The algorithm also guarantees to run in O(n log n) time
// instead of the standard O(n²) time.
//
// Some systems call this approach a “patience diff,” named for
// the “patience sorting” algorithm, itself named for a solitaire card game.
// We avoid that name for two reasons. First, the name has been used
// for a few different variants of the algorithm, so it is imprecise.
// Second, the name is frequently interpreted as meaning that you have
// to wait longer (to be patient) for the diff, meaning that it is a slower algorithm,
// when in fact the algorithm is faster than the standard one.
func Diff(oldName string, old []byte, newName string, new []byte) []byte {
	if bytes.Equal(old, new) {
		return nil
	}
	x := lines(old)
	y := lines(new)

	// Print diff header.
	var out bytes.Buffer
	fmt.Fprintf(&out, "diff %s %s\n", oldName, newName)
	fmt.Fprintf(&out, "--- %s\n", oldName)
	fmt.Fprintf(&out, "+++ %s\n", newName)

	// Loop over matches to consider,
	// expanding each match to include surrounding lines,
	// and then printing diff chunks.
	// To avoid setup/teardown cases outside the loop,
	// tgs returns a leading {0,0} and trailing {len(x), len(y)} pair
	// in the sequence of matches.
	var (
		done  pair     // printed up to x[:done.x] and y[:done.y]
		chunk pair     // start lines of current chunk
		count pair     // number of lines from each side in current chunk
		ctext []string // lines for current chunk
	)
	for _, m := range tgs(x, y) {
		if m.x < done.x {
			// Already handled scanning forward from earlier match.
			continue
		}

		// Expand matching lines as far possible,
		// establishing that x[start.x:end.x] == y[start.y:end.y].
		// Note that on the first (or last) iteration we may (or definitely do)
		// have an empty match: start.x==end.x and start.y==end.y.
		start := m
		for start.x > done.x && start.y > done.y && x[start.x-1] == y[start.y-1] {
			start.x--
			start.y--
		}
		end := m
		for end.x < len(x) && end.y < len(y) && x[end.x] == y[end.y] {
			end.x++
			end.y++
		}

		// Emit the mismatched lines before start into this chunk.
		// (No effect on first sentinel iteration, when start = {0,0}.)
		for _, s := range x[done.x:start.x] {
			ctext = append(ctext, "-"+s)
			count.x++
		}
		for _, s := range y[done.y:start.y] {
			ctext = append(ctext, "+"+s)
			count.y++
		}

		// If we're not at EOF and have too few common lines,
		// the chunk includes all the common lines and continues.
		const C = 3 // number of context lines
		if (end.x < len(x) || end.y < len(y)) &&
			(end.x-start.x < C || (len(ctext) > 0 && end.x-start.x < 2*C)) {
			for _, s := range x[start.x:end.x] {
				ctext = append(ctext, " "+s)
				count.x++
				count.y++
			}
			done = end
			continue
		}

		// End chunk with common lines for context.
		if len(ctext) > 0 {
			n := end.x - start.x
			if n > C {
				n = C
			}
			for _, s := range x[start.x : start.x+n] {
				ctext = append(ctext, " "+s)
				count.x++
				count.y++
			}
			done = pair{start.x + n, start.y + n}

			// Format and emit chunk.
			// Convert line numbers to 1-indexed.
			// Special case: empty file shows up as 0,0 not 1,0.
			if count.x > 0 {
				chunk.x++
			}
			if count.y > 0 {
				chunk.y++
			}
			fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", chunk.x, count.x, chunk.y, count.y)
			for _, s := range ctext {
				out.WriteString(s)
			}
			count.x = 0
			count.y = 0
			ctext = ctext[:0]
		}

		// If we reached EOF, we're done.
		if end.x >= len(x) && end.y >= len(y) {
			break
		}

		// Otherwise start a new chunk.
		chunk = pair{end.x - C, end.y - C}
		for _, s := range x[chunk.x:end.x] {
			ctext = append(ctext, " "+s)
			count.x++
			count.y++
		}
		done = end
	}

	return out.Bytes()
}

// lines returns the lines in the file x, including newlines.
// If the file does not end in a newline, one is supplied
// along with a warning about the missing newline.
func lines(x []byte) []string {
	l := strings.SplitAfter(string(x), "\n")
	if l[len(l)-1] == "" {
		l = l[:len(l)-1]
	} else {
		// Treat last line as having a message about the missing newline attached,
		// using the same text as BSD/GNU diff (including the leading backslash).
		l[len(l)-1] += "\n\\ No newline at end of file\n"
	}
	return l
}

// tgs returns the pairs of indexes of the longest common subsequence
// of unique lines in x and y, where a unique line is one that appears
// once in x and once in y.
//
// The longest common subsequence algorithm is as described in
// Thomas G. Szymanski, “A Special Case of the Maximal Common
// Subsequence Problem,” Princeton TR #170 (January 1975),
// available at https://research.swtch.com/tgs170.pdf.
func tgs(x, y []string) []pair {
	// Count the number of times each string appears in a and b.
	// We only care about 0, 1, many, counted as 0, -1, -2
	// for the x side and 0, -4, -8 for the y side.
	// Using negative numbers now lets us distinguish positive line numbers later.
	m := make(map[string]int)
	for _, s := range x {
		if c := m[s]; c > -2 {
			m[s] = c - 1
		}
	}
	for _, s := range y {
		if c := m[s]; c > -8 {
			m[s] = c - 4
		}
	}

	// Now unique strings can be identified by m[s] = -1+-4.
	//
	// Gather the indexes of those strings in x and y, building:
	//	xi[i] = increasing indexes of unique strings in x.
	//	yi[i] = increasing indexes of unique strings in y.
	//	inv[i] = index j such that x[xi[i]] = y[yi[j]].
	var xi, yi, inv []int
	for i, s := range y {
		if m[s] == -1+-4 {
			m[s] = len(yi)
			yi = append(yi, i)
		}
	}
	for i, s := range x {
		if j, ok := m[s]; ok && j >= 0 {
			xi = append(xi, i)
			inv = append(inv, j)
		}
	}

	// Apply Algorithm A from Szymanski's paper.
	// In those terms, A = J = inv and B = [0, n).
	// We add sentinel pairs {0,0}, and {len(x),len(y)}
	// to the returned sequence, to help the processing loop.
	J := inv
	n := len(xi)
	T := make([]int, n)
	L := make([]int, n)
	for i := range T {
		T[i] = n + 1
	}
	for i := 0; i < n; i++ {
		k := sort.Search(n, func(k int) bool {
			return T[k] >= J[i]
		})
		T[k] = J[i]
		L[i] = k + 1
	}
	k := 0
	for _, v := range L {
		if k < v {
			k = v
		}
	}
	seq := make([]pair, 2+k)
	seq[1+k] = pair{len(x), len(y)} // sentinel at end
	lastj := n
	for i := n - 1; i >= 0; i-- {
		if L[i] == k && J[i] < lastj {
			seq[k] = pair{xi[i], yi[J[i]]}
			k--
		}
	}
	seq[0] = pair{0, 0} // sentinel at start
	return seq
}
