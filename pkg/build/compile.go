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

	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
	"gopkg.in/yaml.v3"
)

func (b *Build) Compile() error {
	cfg := b.Configuration
	pb := &PipelineBuild{
		Build:   b,
		Package: &cfg.Package,
	}

	for i := range cfg.Pipeline {
		if err := b.compilePipeline(pb, &cfg.Pipeline[i]); err != nil {
			return fmt.Errorf("compiling Pipeline[%d]: %w", i, err)
		}

		if err := b.gatherDeps(&cfg.Pipeline[i]); err != nil {
			return fmt.Errorf("gathering deps for Pipeline[%d]: %w", i, err)
		}
	}

	for _, sp := range cfg.Subpackages {
		pb.Subpackage = &sp

		if sp.If != "" {
			mutated, err := MutateWith(pb, map[string]string{})
			if err != nil {
				return fmt.Errorf("creating subpackage map: %w", err)
			}
			sp.If, err = util.MutateAndQuoteStringFromMap(mutated, sp.If)
			if err != nil {
				return fmt.Errorf("mutating subpackage if: %w", err)
			}
		}

		for i := range sp.Pipeline {
			if err := b.compilePipeline(pb, &sp.Pipeline[i]); err != nil {
				return fmt.Errorf("compiling subpackage %q Pipeline[%d]: %w", sp.Name, i, err)
			}
			if err := b.gatherDeps(&sp.Pipeline[i]); err != nil {
				return fmt.Errorf("gathering deps for subpackage %q Pipeline[%d]: %w", sp.Name, i, err)
			}
		}
	}

	b.Configuration.Environment.Contents.Packages = util.Dedup(b.Configuration.Environment.Contents.Packages)

	return nil
}

func (b *Build) compilePipeline(pb *PipelineBuild, pipeline *config.Pipeline) error {
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
		return fmt.Errorf("unable to validate with: %w", err)
	}

	mutated, err := MutateWith(pb, validated)
	if err != nil {
		return fmt.Errorf("mutating with: %w", err)
	}

	// allow input mutations on needs.packages
	if pipeline.Needs != nil {
		for i := range pipeline.Needs.Packages {
			pipeline.Needs.Packages[i], err = util.MutateStringFromMap(mutated, pipeline.Needs.Packages[i])
			if err != nil {
				return fmt.Errorf("mutating needs: %w", err)
			}
		}
	}

	if pipeline.WorkDir != "" {
		pipeline.WorkDir, err = util.MutateStringFromMap(mutated, pipeline.WorkDir)
		if err != nil {
			return fmt.Errorf("mutating workdir: %w", err)
		}
	}

	pipeline.Runs, err = util.MutateStringFromMap(mutated, pipeline.Runs)
	if err != nil {
		return fmt.Errorf("mutating runs: %w", err)
	}

	if pipeline.If != "" {
		pipeline.If, err = util.MutateAndQuoteStringFromMap(mutated, pipeline.If)
		if err != nil {
			return fmt.Errorf("mutating if: %w", err)
		}
	}

	for i := range pipeline.Pipeline {
		p := &pipeline.Pipeline[i]
		p.With = util.RightJoinMap(mutated, p.With)

		if err := b.compilePipeline(pb, p); err != nil {
			return fmt.Errorf("compiling Pipeline[%d]: %w", i, err)
		}
	}

	// Clear these now that we're done with them.
	pipeline.Inputs = nil
	pipeline.With = nil

	return nil
}

func identity(p *config.Pipeline) string {
	if p.Name != "" {
		return p.Name
	}
	if p.Uses != "" {
		return p.Uses
	}
	return "???"
}

func (b *Build) gatherDeps(pipeline *config.Pipeline) error {
	ic := &b.Configuration.Environment
	id := identity(pipeline)

	if pipeline.If != "" {
		if result, err := cond.Evaluate(pipeline.If); err != nil {
			return fmt.Errorf("evaluating conditional %q: %w", pipeline.If, err)
		} else if !result {
			return nil
		}
	}

	if pipeline.Needs != nil {
		for _, pkg := range pipeline.Needs.Packages {
			b.Logger.Printf("  adding package %q for pipeline %q", pkg, id)
		}
		ic.Contents.Packages = append(ic.Contents.Packages, pipeline.Needs.Packages...)

		// Clear this now that we're done with it.
		pipeline.Needs = nil
	}

	for _, p := range pipeline.Pipeline {
		if err := b.gatherDeps(&p); err != nil {
			return fmt.Errorf("gathering deps: %w", err)
		}
	}

	return nil
}
