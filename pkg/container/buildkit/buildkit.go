package buildkit

import (
	"context"
	"io"
	"os"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"

	"chainguard.dev/melange/pkg/container"
	"github.com/chainguard-dev/clog"
	"github.com/containerd/console"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/util/progress/progressui"
	"golang.org/x/sync/errgroup"
)

type runner struct {
	client *client.Client
}

// TODO: This should just take a client, really.
func NewRunner(ctx context.Context, addr string) (container.Runner, error) {
	client, err := client.New(ctx, addr)
	if err != nil {
		return nil, err
	}

	return &runner{
		client: client,
	}, nil
}

func (r *runner) Close() error {
	return r.client.Close()
}

func (r *runner) Name() string {
	return "buildkit"
}

func (r *runner) TempDir() string {
	return ""
}

func (r *runner) TestUsability(ctx context.Context) bool {
	log := clog.FromContext(ctx)
	info, err := r.client.Info(ctx)
	if err != nil {
		return false
	}
	log.Infof("buildkit version: %q", info.BuildkitVersion)
	return err == nil
}

func (r *runner) StartPod(ctx context.Context, cfg *container.Config) error {
	llb.Image(cfg.ImgRef).Run(llb.Shlex("echo 'hi'")).Root()
	return nil
}

func (r *runner) TerminatePod(ctx context.Context, cfg *container.Config) error {
	return nil
}

func (r *runner) Run(ctx context.Context, cfg *container.Config, cmd ...string) error {
	state := llb.Image(cfg.ImgRef)
	for k, v := range cfg.Environment {
		state = state.AddEnv(k, v)
	}
	state = state.Run(llb.Args(cmd)).Root()

	def, err := state.Marshal(ctx)
	if err != nil {
		return err
	}

	solveOpts := client.SolveOpt{}
	ch := make(chan *client.SolveStatus)
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		_, err := r.client.Solve(ctx, def, solveOpts, ch)
		return err
	})
	eg.Go(func() error {
		_, err := progressui.DisplaySolveStatus(ctx, console.Current(), os.Stderr, ch)
		return err
	})

	return eg.Wait()
}

func (r *runner) OCIImageLoader() container.Loader {
	return &loader{}
}

func (r *runner) WorkspaceTar(ctx context.Context, cfg *container.Config) (io.ReadCloser, error) {
	return nil, nil
}

type loader struct{}

func (l *loader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	return "", nil
}

func (l *loader) RemoveImage(ctx context.Context, ref string) error {
	return nil
}
