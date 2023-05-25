// Copyright 2022 Chainguard, Inc.
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

package index

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	apko_log "chainguard.dev/apko/pkg/log"
	sign "github.com/chainguard-dev/go-apk/pkg/signature"
	"github.com/korovkin/limiter"
	"github.com/sirupsen/logrus"
	apkrepo "gitlab.alpinelinux.org/alpine/go/repository"
	"go.opentelemetry.io/otel"
)

type Context struct {
	PackageFiles       []string
	IndexFile          string
	MergeIndexFileFlag bool
	SigningKey         string
	Logger             *logrus.Logger
	ExpectedArch       string
}

type Option func(*Context) error

func WithMergeIndexFileFlag(mergeFlag bool) Option {
	return func(c *Context) error {
		c.MergeIndexFileFlag = mergeFlag
		return nil
	}
}

func WithIndexFile(indexFile string) Option {
	return func(c *Context) error {
		c.IndexFile = indexFile
		return nil
	}
}

func WithPackageFiles(packageFiles []string) Option {
	return func(c *Context) error {
		c.PackageFiles = append(c.PackageFiles, packageFiles...)
		return nil
	}
}

func WithPackageDir(packageDir string) Option {
	return func(c *Context) error {
		files, err := os.ReadDir(packageDir)
		if err != nil {
			return fmt.Errorf("unable to list packages: %w", err)
		}
		apkFiles := []string{}
		for _, file := range files {
			n := filepath.Join(packageDir, file.Name())
			if !file.IsDir() && strings.HasSuffix(n, ".apk") {
				apkFiles = append(apkFiles, n)
			}
		}

		c.PackageFiles = append(c.PackageFiles, apkFiles...)
		return nil
	}
}

func WithSigningKey(signingKey string) Option {
	return func(c *Context) error {
		c.SigningKey = signingKey
		return nil
	}
}

// WithExpectedArch sets the expected package architecture.  Any packages with
// an unexpected architecture will not be indexed.
func WithExpectedArch(expectedArch string) Option {
	return func(c *Context) error {
		c.ExpectedArch = expectedArch
		return nil
	}
}

func New(opts ...Option) (*Context, error) {
	c := Context{
		PackageFiles: []string{},
		Logger: &logrus.Logger{
			Out:       os.Stderr,
			Formatter: &apko_log.Formatter{},
			Hooks:     make(logrus.LevelHooks),
			Level:     logrus.InfoLevel,
		},
	}

	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}

	return &c, nil
}

func (c *Context) GenerateIndex(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "GenerateIndex")
	defer span.End()

	packages := make([]*apkrepo.Package, len(c.PackageFiles))
	var mtx sync.Mutex

	g := limiter.NewConcurrencyLimiterForIO(limiter.DefaultConcurrencyLimitIO)

	for i, apkFile := range c.PackageFiles {
		i, apkFile := i, apkFile // capture the loop variables
		if _, err := g.Execute(func() {
			c.Logger.Printf("processing package %s", apkFile)
			f, err := os.Open(apkFile)
			if err != nil {
				// nolint:errcheck
				g.FirstErrorStore(fmt.Errorf("failed to open package %s: %w", apkFile, err))
				return
			}
			defer f.Close()
			pkg, err := apkrepo.ParsePackage(f)
			if err != nil {
				// nolint:errcheck
				g.FirstErrorStore(fmt.Errorf("failed to parse package %s: %w", apkFile, err))
				return
			}

			if c.ExpectedArch != "" && pkg.Arch != c.ExpectedArch {
				c.Logger.Printf("WARNING: %s-%s: found unexpected architecture %s, expecting %s",
					pkg.Name, pkg.Version, pkg.Arch, c.ExpectedArch)
				return
			}

			mtx.Lock()
			packages[i] = pkg
			mtx.Unlock()
		}); err != nil {
			return fmt.Errorf("executing processor function: %w", err)
		}
	}
	if err := g.WaitAndClose(); err != nil {
		return err
	}

	if err := g.FirstErrorGet(); err != nil {
		return err
	}

	var index *apkrepo.ApkIndex

	if c.MergeIndexFileFlag {
		originApkIndex, err := os.Open(c.IndexFile)
		if err == nil {
			index, err = apkrepo.IndexFromArchive(originApkIndex)
			if err != nil {
				return fmt.Errorf("failed to read apkindex from archive file: %w", err)
			}

			for _, pkg := range packages {
				found := false

				for _, p := range index.Packages {
					if pkg.Name == p.Name && pkg.Version == p.Version {
						found = true
						p = pkg
					}
				}
				if !found {
					index.Packages = append(index.Packages, pkg)
				}
			}
		} else {
			// indexFile not exists, we just create a new one
			index = &apkrepo.ApkIndex{}

			for _, pkg := range packages {
				if pkg != nil {
					index.Packages = append(index.Packages, pkg)
				}
			}
		}
	} else {
		index = &apkrepo.ApkIndex{}

		for _, pkg := range packages {
			if pkg != nil {
				index.Packages = append(index.Packages, pkg)
			}
		}
	}

	pkgNames := make([]string, 0, len(packages))
	for _, p := range packages {
		if p != nil {
			pkgNames = append(pkgNames, fmt.Sprintf("%s-%s", p.Name, p.Version))
		}
	}

	c.Logger.Printf("generating index at %s with new packages: %v", c.IndexFile, pkgNames)
	archive, err := apkrepo.ArchiveFromIndex(index)
	if err != nil {
		return fmt.Errorf("failed to create archive from index object: %w", err)
	}
	outFile, err := os.Create(c.IndexFile)
	if err != nil {
		return fmt.Errorf("failed to create archive file: %w", err)
	}
	defer outFile.Close()
	if _, err = io.Copy(outFile, archive); err != nil {
		return fmt.Errorf("failed to write contents to archive file: %w", err)
	}

	if c.SigningKey != "" {
		c.Logger.Printf("signing apk index at %s", c.IndexFile)
		if err := sign.SignIndex(c.Logger, c.SigningKey, c.IndexFile); err != nil {
			return fmt.Errorf("failed to sign apk index: %w", err)
		}
	}

	return nil
}
