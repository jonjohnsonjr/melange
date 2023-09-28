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
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
)

func Scan() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan an existing APK to generate .PKGINFO",
		Example: `melange scan < foo.apk`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ScanCmd(cmd.Context(), cmd.InOrStdin())
		},
	}
	return cmd
}

func ScanCmd(ctx context.Context, in io.Reader) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "ScanCmd")
	defer span.End()

	// 1. Parse control section.
	// 2. Generate config.Package.
	// 3. Create build.PackageBuild.
	// 4. Set size
	// 5. Set hash
	// 6. Call GenerateControlData

	pkgConfig := config.Package{}

	pkg, err := build.NewPackageContext(&pkgConfig)
	if err != nil {
		return err
	}

	// TODO
	installedSize := int64(0)
	dataHash := ""

	pb := build.PackageBuild{
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
		DataHash:      dataHash,
		// TODO
		// Arch:         pb.Build.Arch.ToAPK(),
		// Logger:       pb.Build.Logger,
		// OutDir:       filepath.Join(pb.Build.OutDir, pb.Build.Arch.ToAPK()),
	}

	if err := pb.GenerateDependencies(); err != nil {
		return err
	}

	return nil
}

type pkginfo struct {
	name    string
	version string
	origin  string
	commit  string
}

func parsePkgInfo(in io.Reader) {
	scanner := bufio.NewScanner(in)

	pkg := pkginfo{}

	for scanner.Scan() {
		line := scanner.Text()

		before, after, ok := strings.Cut(line, "=")
		if !ok {

			fmt.Fprintf(w, "%s\n", line)

			continue
		}

		before = strings.TrimSpace(before)
		after = strings.TrimSpace(after)

		switch before {
		case "pkgname":
			pkg.name = after
		case "origin":
			pkg.origin = after
		case "commit":
			pkg.commit = after
		}

		switch before {
		case "pkgname":
			href := fmt.Sprintf("%s?depend=%s", apkindex, url.QueryEscape(after))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "depend":
			href := fmt.Sprintf("%s?provide=%s", apkindex, url.QueryEscape(after))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "provides":
			p, _, ok := strings.Cut(after, "=")
			if !ok {
				p = after
			}
			href := fmt.Sprintf("%s?depend=%s", apkindex, url.QueryEscape(p))
			fmt.Fprintf(w, "%s = <a href=%q>%s</a>\n", before, href, after)
		case "size":
			i, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as int: %w", after, err)
			}
			fmt.Fprintf(w, "%s = <a title=%q href=%q>%s</a>\n", before, humanize.Bytes(uint64(i)), sizeHref, after)
		case "builddate":
			sec, err := strconv.ParseInt(after, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing %q as timestamp: %w", after, err)
			}
			t := time.Unix(sec, 0)
			fmt.Fprintf(w, "%s = <span title=%q>%s</span>\n", before, t.String(), after)
		default:
			fmt.Fprintf(w, "%s\n", line)
		}
	}
}
