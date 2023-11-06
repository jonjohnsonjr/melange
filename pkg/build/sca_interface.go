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

package build

import (
	"fmt"
	"path/filepath"

	"chainguard.dev/apko/pkg/log"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/sca"
)

// SCABuildInterface provides an implementation of SCAHandle which maps to
// a package build object.
type SCABuildInterface struct {
	// PackageBuild represents the underlying package build object.
	PackageBuild *PackageBuild
}

// PackageName returns the currently built package name.
func (sca *SCABuildInterface) PackageName() string {
	return sca.PackageBuild.PackageName
}

// RelativeNames returns all the package names relating to the package being
// built.
func (sca *SCABuildInterface) RelativeNames() []string {
	targets := []string{sca.PackageBuild.Origin.Name}

	for _, target := range sca.PackageBuild.Build.Configuration.Subpackages {
		targets = append(targets, target.Name)
	}

	return targets
}

// Version returns the version of the package being built including epoch.
func (sca *SCABuildInterface) Version() string {
	return fmt.Sprintf("%s-r%d", sca.PackageBuild.Origin.Version, sca.PackageBuild.Origin.Epoch)
}

// FilesystemForRelative implements an abstract filesystem for any of the packages being
// built.
func (scabi *SCABuildInterface) FilesystemForRelative(pkgName string) (sca.SCAFS, error) {
	pkgDir := filepath.Join(scabi.PackageBuild.Build.WorkspaceDir, "melange-out", pkgName)
	rlFS := readlinkFS(pkgDir)
	scaFS, ok := rlFS.(sca.SCAFS)
	if !ok {
		return nil, fmt.Errorf("SCAFS not implemented")
	}

	return scaFS, nil
}

// Filesystem implements an abstract filesystem providing access to a package filesystem.
func (sca *SCABuildInterface) Filesystem() (sca.SCAFS, error) {
	return sca.FilesystemForRelative(sca.PackageName())
}

// Logger returns a logger for use by the SCA engine.
func (sca *SCABuildInterface) Logger() log.Logger {
	return sca.PackageBuild.Logger
}

// Options returns the configured SCA engine options for the package being built.
func (sca *SCABuildInterface) Options() config.PackageOption {
	if sca.PackageBuild.Options == nil {
		return config.PackageOption{}
	}
	return *sca.PackageBuild.Options
}

// BaseDependencies returns the base dependencies for the package being built.
func (sca *SCABuildInterface) BaseDependencies() config.Dependencies {
	return sca.PackageBuild.Dependencies
}
