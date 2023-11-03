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

	"go.opentelemetry.io/otel"

	"gopkg.in/yaml.v3"

	apko_log "chainguard.dev/apko/pkg/log"

	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/logger"
	"chainguard.dev/melange/pkg/util"
)

type PipelineContext struct {
	Pipeline *config.Pipeline
	logger   apko_log.Logger
	steps    int
}

func NewPipelineContext(p *config.Pipeline, log apko_log.Logger) *PipelineContext {
	if log == nil {
		log = logger.NopLogger{}
	}
	return &PipelineContext{
		Pipeline: p,
		logger:   log,
		steps:    0,
	}
}

type PipelineBuild struct {
	Build      *Build
	Package    *config.Package
	Subpackage *config.Subpackage
}

func (pctx *PipelineContext) Identity() string {
	if pctx.Pipeline.Name != "" {
		return pctx.Pipeline.Name
	}
	if pctx.Pipeline.Uses != "" {
		return pctx.Pipeline.Uses
	}
	return "???"
}

func MutateWith(pb *PipelineBuild, with map[string]string) (map[string]string, error) {
	nw, err := substitutionMap(pb.Build, pb.Package, pb.Subpackage)
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

func substitutionMap(b *Build, pkg *config.Package, spkg *config.Subpackage) (map[string]string, error) {
	nw := map[string]string{
		config.SubstitutionPackageName:          pkg.Name,
		config.SubstitutionPackageVersion:       pkg.Version,
		config.SubstitutionPackageEpoch:         strconv.FormatUint(pkg.Epoch, 10),
		config.SubstitutionPackageFullVersion:   fmt.Sprintf("%s-r%s", config.SubstitutionPackageVersion, config.SubstitutionPackageEpoch),
		config.SubstitutionTargetsDestdir:       fmt.Sprintf("/home/build/melange-out/%s", pkg.Name),
		config.SubstitutionTargetsContextdir:    fmt.Sprintf("/home/build/melange-out/%s", pkg.Name),
		config.SubstitutionHostTripletGnu:       b.BuildTripletGnu(),
		config.SubstitutionHostTripletRust:      b.BuildTripletRust(),
		config.SubstitutionCrossTripletGnuGlibc: b.Arch.ToTriplet("gnu"),
		config.SubstitutionCrossTripletGnuMusl:  b.Arch.ToTriplet("musl"),
		config.SubstitutionBuildArch:            b.Arch.ToAPK(),
	}

	// Retrieve vars from config
	subst_nw, err := b.Configuration.GetVarsFromConfig()
	if err != nil {
		return nil, err
	}

	for k, v := range subst_nw {
		nw[k] = v
	}

	// Perform substitutions on current map
	if err := b.Configuration.PerformVarSubstitutions(nw); err != nil {
		return nil, err
	}

	if spkg != nil {
		nw[config.SubstitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", spkg.Name)
		nw[config.SubstitutionTargetsContextdir] = nw[config.SubstitutionSubPkgDir]
	}

	packageNames := []string{pkg.Name}
	for _, sp := range b.Configuration.Subpackages {
		packageNames = append(packageNames, sp.Name)
	}

	for _, pn := range packageNames {
		k := fmt.Sprintf("${{targets.package.%s}}", pn)
		nw[k] = fmt.Sprintf("/home/build/melange-out/%s", pn)
	}

	for k := range b.Configuration.Options {
		nk := fmt.Sprintf("${{options.%s.enabled}}", k)
		nw[nk] = "false"
	}

	for _, opt := range b.EnabledBuildOptions {
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

func (b *Build) loadPipeline(pb *PipelineBuild, pipeline *config.Pipeline) error {
	uses, with := pipeline.Uses, pipeline.With

	if uses != "" {
		data, err := loadPipelineData(b.PipelineDir, uses)
		if err != nil {
			data, err = loadPipelineData(b.BuiltinPipelineDir, uses)
			if err != nil {
				data, err = f.ReadFile("pipelines/" + uses + ".yaml")
				if err != nil {
					return fmt.Errorf("unable to load pipeline: %w", err)
				}
			}
		}

		if err := yaml.Unmarshal(data, pipeline); err != nil {
			return fmt.Errorf("unable to parse pipeline %q: %w", uses, err)
		}
	}

	validated, err := validateWith(with, pipeline.Inputs)
	if err != nil {
		return fmt.Errorf("unable to validate pipeline: %w", err)
	}
	pipeline.With, err = MutateWith(pb, validated)
	if err != nil {
		return fmt.Errorf("mutating pipeline: %w", err)
	}

	// allow input mutations on needs.packages
	for i := range pipeline.Needs.Packages {
		pipeline.Needs.Packages[i], err = util.MutateStringFromMap(pipeline.With, pipeline.Needs.Packages[i])
		if err != nil {
			return err
		}
	}

	for i := range pipeline.Pipeline {
		p := &pipeline.Pipeline[i]
		p.With = util.RightJoinMap(pipeline.With, p.With)

		if err := b.loadPipeline(pb, p); err != nil {
			return err
		}
	}

	return nil
}

func (pctx *PipelineContext) loadUse(pb *PipelineBuild, uses string, with map[string]string) error {
	data, err := loadPipelineData(pb.Build.PipelineDir, uses)
	if err != nil {
		data, err = loadPipelineData(pb.Build.BuiltinPipelineDir, uses)
		if err != nil {
			data, err = f.ReadFile("pipelines/" + uses + ".yaml")
			if err != nil {
				return fmt.Errorf("unable to load pipeline: %w", err)
			}
		}
	}

	if err := yaml.Unmarshal(data, &pctx.Pipeline); err != nil {
		return fmt.Errorf("unable to parse pipeline %q: %w", uses, err)
	}

	validated, err := validateWith(with, pctx.Pipeline.Inputs)
	if err != nil {
		return fmt.Errorf("unable to construct pipeline: %w", err)
	}
	pctx.Pipeline.With, err = MutateWith(pb, validated)
	if err != nil {
		return err
	}

	// allow input mutations on needs.packages
	for p := range pctx.Pipeline.Needs.Packages {
		pctx.Pipeline.Needs.Packages[p], err = util.MutateStringFromMap(pctx.Pipeline.With, pctx.Pipeline.Needs.Packages[p])
		if err != nil {
			return err
		}
	}

	for k := range pctx.Pipeline.Pipeline {
		pctx.Pipeline.Pipeline[k].With = util.RightJoinMap(pctx.Pipeline.With, pctx.Pipeline.Pipeline[k].With)
	}

	return nil
}

func (pctx *PipelineContext) dumpWith() {
	for k, v := range pctx.Pipeline.With {
		pctx.logger.Debugf("    %s: %s", k, v)
	}
}

func (pctx *PipelineContext) evalUse(ctx context.Context, pb *PipelineBuild) error {
	spctx := NewPipelineContext(&config.Pipeline{}, pb.Build.Logger)

	if err := spctx.loadUse(pb, pctx.Pipeline.Uses, pctx.Pipeline.With); err != nil {
		return err
	}
	spctx.Pipeline.WorkDir = pctx.Pipeline.WorkDir

	pctx.logger.Printf("  using %s", pctx.Pipeline.Uses)
	spctx.dumpWith()

	ran, err := spctx.Run(ctx, pb)
	if err != nil {
		return err
	}

	if ran {
		pctx.steps++
	}

	return nil
}

// Build a script to run as part of evalRun
func (pctx *PipelineContext) buildEvalRunCommand(debugOption rune, sysPath string, workdir string, fragment string) []string {
	envExport := "export %s='%s'"
	envArr := []string{}
	for k, v := range pctx.Pipeline.Environment {
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

func (pctx *PipelineContext) evalRun(ctx context.Context, pb *PipelineBuild) error {
	var err error
	pctx.Pipeline.With, err = MutateWith(pb, pctx.Pipeline.With)
	if err != nil {
		return err
	}
	pctx.dumpWith()

	debugOption := ' '
	if pb.Build.Debug {
		debugOption = 'x'
	}

	sysPath := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	workdir := "/home/build"
	if pctx.Pipeline.WorkDir != "" {
		workdir, err = util.MutateStringFromMap(pctx.Pipeline.With, pctx.Pipeline.WorkDir)
		if err != nil {
			return err
		}
	}

	fragment, err := util.MutateStringFromMap(pctx.Pipeline.With, pctx.Pipeline.Runs)
	if err != nil {
		return err
	}

	command := pctx.buildEvalRunCommand(debugOption, sysPath, workdir, fragment)
	config := pb.Build.WorkspaceConfig()
	if err := pb.Build.Runner.Run(ctx, config, command...); err != nil {
		return err
	}

	return nil
}

func (pctx *PipelineContext) evaluateBranchConditional(pb *PipelineBuild) bool {
	if pctx.Pipeline.If == "" {
		return true
	}

	lookupWith := func(key string) (string, error) {
		mutated, err := MutateWith(pb, pctx.Pipeline.With)
		if err != nil {
			return "", err
		}
		nk := fmt.Sprintf("${{%s}}", key)
		return mutated[nk], nil
	}

	result, err := cond.Evaluate(pctx.Pipeline.If, lookupWith)
	if err != nil {
		panic(fmt.Errorf("could not evaluate if-conditional '%s': %w", pctx.Pipeline.If, err))
	}

	pctx.logger.Printf("evaluating if-conditional '%s' --> %t", pctx.Pipeline.If, result)

	return result
}

func (pctx *PipelineContext) isContinuationPoint(pb *PipelineBuild) bool {
	b := pb.Build

	if b.ContinueLabel == "" {
		return true
	}

	if b.ContinueLabel == pctx.Pipeline.Label {
		b.foundContinuation = true
	}

	return b.foundContinuation
}

func (pctx *PipelineContext) shouldEvaluateBranch(pb *PipelineBuild) bool {
	if !pctx.isContinuationPoint(pb) {
		return false
	}

	return pctx.evaluateBranchConditional(pb)
}

func (pctx *PipelineContext) evaluateBranch(ctx context.Context, pb *PipelineBuild) error {
	if pctx.Identity() != "???" {
		pctx.logger.Printf("running step %s", pctx.Identity())
	}

	if pctx.Pipeline.Uses != "" {
		return pctx.evalUse(ctx, pb)
	}

	if pctx.Pipeline.Runs != "" {
		return pctx.evalRun(ctx, pb)
	}

	return nil
}

func (pctx *PipelineContext) checkAssertions(pb *PipelineBuild) error {
	if pctx.Pipeline.Assertions.RequiredSteps > 0 && pctx.steps < pctx.Pipeline.Assertions.RequiredSteps {
		return fmt.Errorf("pipeline did not run the required %d steps, only %d", pctx.Pipeline.Assertions.RequiredSteps, pctx.steps)
	}

	return nil
}

func (pctx *PipelineContext) Run(ctx context.Context, pb *PipelineBuild) (bool, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "Pipeline.Run")
	defer span.End()

	if pctx.Pipeline.Label != "" && pctx.Pipeline.Label == pb.Build.BreakpointLabel {
		return false, fmt.Errorf("stopping execution at breakpoint: %s", pctx.Pipeline.Label)
	}

	if !pctx.shouldEvaluateBranch(pb) {
		return false, nil
	}

	if err := pctx.evaluateBranch(ctx, pb); err != nil {
		return false, err
	}

	for _, sp := range pctx.Pipeline.Pipeline {
		spctx := NewPipelineContext(&sp, pb.Build.Logger)
		if spctx.Pipeline.WorkDir == "" {
			spctx.Pipeline.WorkDir = pctx.Pipeline.WorkDir
		}

		ran, err := spctx.Run(ctx, pb)

		if err != nil {
			return false, err
		}

		if ran {
			pctx.steps++
		}
	}

	if err := pctx.checkAssertions(pb); err != nil {
		return false, err
	}

	return true, nil
}

// TODO(kaniini): Precompile pipeline before running / evaluating its
// needs.
func (pctx *PipelineContext) ApplyNeeds(pb *PipelineBuild) error {
	ic := &pb.Build.Configuration.Environment

	for _, pkg := range pctx.Pipeline.Needs.Packages {
		pctx.logger.Printf("  adding package %q for pipeline %q", pkg, pctx.Identity())
		ic.Contents.Packages = append(ic.Contents.Packages, pkg)
	}

	if pctx.Pipeline.Uses != "" {
		spctx := NewPipelineContext(nil, pb.Build.Logger)

		if err := spctx.loadUse(pb, pctx.Pipeline.Uses, pctx.Pipeline.With); err != nil {
			return err
		}

		if err := spctx.ApplyNeeds(pb); err != nil {
			return err
		}
	}

	ic.Contents.Packages = util.Dedup(ic.Contents.Packages)

	for _, sp := range pctx.Pipeline.Pipeline {
		spctx := NewPipelineContext(&sp, pb.Build.Logger)

		if err := spctx.ApplyNeeds(pb); err != nil {
			return err
		}
	}

	return nil
}

//go:embed pipelines/*
var f embed.FS
