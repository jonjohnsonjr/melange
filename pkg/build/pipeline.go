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

package build

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
)

type PipelineBuild struct {
	Build      *Build
	Package    *config.Package
	Subpackage *config.Subpackage
}

func MutateWith(pb *PipelineBuild, with map[string]string) (map[string]string, error) {
	nw, err := substitutionMap(pb)
	if err != nil {
		return nil, err
	}

	for k, v := range with {
		// already mutated?
		if strings.HasPrefix(k, "${{") {
			nw[k] = v
		} else {
			nk := fmt.Sprintf("${{inputs.%s}}", k)
			nw[nk] = v
		}
	}

	// do the actual mutations
	for k, v := range nw {
		nval, err := util.MutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}
		nw[k] = nval
	}

	return nw, nil
}

func substitutionMap(pb *PipelineBuild) (map[string]string, error) {
	nw := map[string]string{
		config.SubstitutionPackageName:          pb.Package.Name,
		config.SubstitutionPackageVersion:       pb.Package.Version,
		config.SubstitutionPackageEpoch:         strconv.FormatUint(pb.Package.Epoch, 10),
		config.SubstitutionPackageFullVersion:   fmt.Sprintf("%s-r%s", config.SubstitutionPackageVersion, config.SubstitutionPackageEpoch),
		config.SubstitutionTargetsDestdir:       fmt.Sprintf("/home/build/melange-out/%s", pb.Package.Name),
		config.SubstitutionTargetsContextdir:    fmt.Sprintf("/home/build/melange-out/%s", pb.Package.Name),
		config.SubstitutionHostTripletGnu:       pb.Build.BuildTripletGnu(),
		config.SubstitutionHostTripletRust:      pb.Build.BuildTripletRust(),
		config.SubstitutionCrossTripletGnuGlibc: pb.Build.Arch.ToTriplet("gnu"),
		config.SubstitutionCrossTripletGnuMusl:  pb.Build.Arch.ToTriplet("musl"),
		config.SubstitutionBuildArch:            pb.Build.Arch.ToAPK(),
	}

	// Retrieve vars from config
	subst_nw, err := pb.Build.Configuration.GetVarsFromConfig()
	if err != nil {
		return nil, err
	}

	for k, v := range subst_nw {
		nw[k] = v
	}

	// Perform substitutions on current map
	if err := pb.Build.Configuration.PerformVarSubstitutions(nw); err != nil {
		return nil, err
	}

	if pb.Subpackage != nil {
		nw[config.SubstitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", pb.Subpackage.Name)
		nw[config.SubstitutionTargetsContextdir] = nw[config.SubstitutionSubPkgDir]
	}

	packageNames := []string{pb.Package.Name}
	for _, sp := range pb.Build.Configuration.Subpackages {
		packageNames = append(packageNames, sp.Name)
	}

	for _, pn := range packageNames {
		k := fmt.Sprintf("${{targets.package.%s}}", pn)
		nw[k] = fmt.Sprintf("/home/build/melange-out/%s", pn)
	}

	for k := range pb.Build.Configuration.Options {
		nk := fmt.Sprintf("${{options.%s.enabled}}", k)
		nw[nk] = "false"
	}

	for _, opt := range pb.Build.EnabledBuildOptions {
		nk := fmt.Sprintf("${{options.%s.enabled}}", opt)
		nw[nk] = "true"
	}

	return nw, nil
}

func validateWith(data map[string]string, inputs map[string]config.Input) (map[string]string, error) {
	if data == nil {
		data = make(map[string]string)
	}

	for k, v := range inputs {
		if data[k] == "" && v.Default != "" {
			data[k] = v.Default
		}

		if v.Required && data[k] == "" {
			return data, fmt.Errorf("required input %q for pipeline is missing", k)
		}
	}

	return data, nil
}

func loadPipelineData(dir string, uses string) ([]byte, error) {
	if dir == "" {
		return []byte{}, fmt.Errorf("pipeline directory not specified")
	}

	data, err := os.ReadFile(filepath.Join(dir, uses+".yaml"))
	if err != nil {
		return []byte{}, err
	}

	return data, nil
}

// Build a script to run as part of evalRun
func buildEvalRunCommand(pipeline *config.Pipeline, debugOption rune, sysPath string, workdir string, fragment string) []string {
	envExport := "export %s='%s'"
	envArr := []string{}
	for k, v := range pipeline.Environment {
		envArr = append(envArr, fmt.Sprintf(envExport, k, v))
	}
	envString := strings.Join(envArr, "\n")
	script := fmt.Sprintf(`set -e%c
export PATH='%s'
%s
[ -d '%s' ] || mkdir -p '%s'
cd '%s'
%s
exit 0`, debugOption, sysPath, envString, workdir, workdir, workdir, fragment)
	return []string{"/bin/sh", "-c", script}
}

func (b *Build) run(ctx context.Context, pipeline *config.Pipeline) (bool, error) {
	if b.BreakpointLabel != "" && b.BreakpointLabel == pipeline.Label {
		return false, fmt.Errorf("stopping execution at breakpoint: %s", pipeline.Label)
	}

	if b.ContinueLabel != "" {
		if b.ContinueLabel == pipeline.Label {
			b.foundContinuation = true
		}

		if !b.foundContinuation {
			// TODO: Consider allowing continue labels on nested pipelines.
			return false, nil
		}
	}

	if result, err := b.shouldRun(pipeline.If); !result {
		return result, err
	}

	debugOption := ' '
	if b.Debug {
		debugOption = 'x'
	}

	sysPath := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	workdir := "/home/build"
	if pipeline.WorkDir != "" {
		workdir = pipeline.WorkDir
	}

	command := buildEvalRunCommand(pipeline, debugOption, sysPath, workdir, pipeline.Runs)
	config := b.WorkspaceConfig()
	if err := b.Runner.Run(ctx, config, command...); err != nil {
		return false, err
	}

	steps := 0

	for _, p := range pipeline.Pipeline {
		if ran, err := b.run(ctx, &p); err != nil {
			return false, fmt.Errorf("unable to run pipeline: %w", err)
		} else if ran {
			steps++
		}
	}

	if assert := pipeline.Assertions; assert != nil {
		if want := assert.RequiredSteps; want != steps {
			return false, fmt.Errorf("pipeline did not run the required %d steps, only %d", want, steps)
		}
	}

	return true, nil
}

//go:embed pipelines/*
var f embed.FS
