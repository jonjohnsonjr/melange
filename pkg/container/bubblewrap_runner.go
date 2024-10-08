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

package container

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/internal/logwriter"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"go.opentelemetry.io/otel"
)

var _ Debugger = (*bubblewrap)(nil)

const BubblewrapName = "bubblewrap"

type pod struct {
	pid int

	cmd *exec.Cmd
}

type bubblewrap struct {
	pods map[string]*pod
}

// BubblewrapRunner returns a Bubblewrap Runner implementation.
func BubblewrapRunner() Runner {
	return &bubblewrap{
		pods: make(map[string]*pod),
	}
}

func (bw *bubblewrap) Close() error {
	return nil
}

// Name name of the runner
func (bw *bubblewrap) Name() string {
	return BubblewrapName
}

// Run runs a Bubblewrap task given a Config and command string.
func (bw *bubblewrap) Run(ctx context.Context, cfg *Config, envOverride map[string]string, args ...string) error {
	pod, ok := bw.pods[cfg.PodID]
	if !ok {
		return fmt.Errorf("pod %q not found", cfg.PodID)
	}

	execCmd := bw.cmd(ctx, pod, cfg, false, args...)

	log := clog.FromContext(ctx)
	stdout, stderr := logwriter.New(log.Info), logwriter.New(log.Warn)
	defer stdout.Close()
	defer stderr.Close()

	execCmd.Stdout = stdout
	execCmd.Stderr = stderr

	return execCmd.Run()
}

func (bw *bubblewrap) cmd(ctx context.Context, pod *pod, cfg *Config, debug bool, args ...string) *exec.Cmd {
	baseargs := []string{
		"--target", strconv.Itoa(pod.pid),
		"--all",
		"--root",
	}

	if cfg.RunAs != "" {
		baseargs = append(baseargs, "--setuid", cfg.RunAs)
	}

	args = append(baseargs, args...)
	execCmd := exec.CommandContext(ctx, "nsenter", args...)

	clog.FromContext(ctx).Infof("executing: %s", strings.Join(execCmd.Args, " "))

	return execCmd
}

func (bw *bubblewrap) Debug(ctx context.Context, cfg *Config, envOverride map[string]string, args ...string) error {
	pod, ok := bw.pods[cfg.PodID]
	if !ok {
		return fmt.Errorf("pod %q not found", cfg.PodID)
	}

	execCmd := bw.cmd(ctx, pod, cfg, true, args...)

	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Stdin = os.Stdin

	return execCmd.Run()
}

// TestUsability determines if the Bubblewrap runner can be used
// as a container runner.
func (bw *bubblewrap) TestUsability(ctx context.Context) bool {
	log := clog.FromContext(ctx)
	if _, err := exec.LookPath("bwrap"); err != nil {
		log.Warnf("cannot use bubblewrap for containers: bwrap not found on $PATH")
		return false
	}

	return true
}

// OCIImageLoader used to load OCI images in, if needed. bubblewrap does not need it.
func (bw *bubblewrap) OCIImageLoader() Loader {
	return &bubblewrapOCILoader{}
}

// TempDir returns the base for temporary directory. For bubblewrap, this is empty.
func (bw *bubblewrap) TempDir() string {
	return ""
}

// StartPod starts a pod if necessary.  On Bubblewrap, we just run
// ldconfig to prime ld.so.cache for glibc < 2.37 builds.
func (bw *bubblewrap) StartPod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "bubblewrap.StartPod")
	defer span.End()

	baseargs := []string{}

	// always be sure to mount the / first!
	baseargs = append(baseargs, "--bind", cfg.ImgRef, "/")

	for _, bind := range cfg.Mounts {
		baseargs = append(baseargs, "--bind", bind.Source, bind.Destination)
	}
	// add the ref of the directory

	baseargs = append(baseargs, "--unshare-pid", "--die-with-parent",
		"--dev", "/dev",
		"--proc", "/proc",
		"--chdir", runnerWorkdir,
		"--clearenv")

	baseargs = append(baseargs, "--unshare-user")
	if cfg.RunAs != "" {
		baseargs = append(baseargs, "--uid", cfg.RunAs)
	}

	if !cfg.Capabilities.Networking {
		baseargs = append(baseargs, "--unshare-net")
	}

	for k, v := range cfg.Environment {
		baseargs = append(baseargs, "--setenv", k, v)
	}

	baseargs = append(baseargs, "/bin/sh", "-c", "[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true && sleep infinity")

	cmd := exec.CommandContext(ctx, "bwrap", baseargs...)

	clog.FromContext(ctx).Infof("executing: %s", strings.Join(cmd.Args, " "))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting pod: %w", err)
	}

	// TODO: Less janky.
	time.Sleep(1 * time.Second)

	rootPid := cmd.Process.Pid

	clog.FromContext(ctx).Infof("got rootPid: %d", rootPid)

	pid, err := getLeafPID(rootPid)
	if err != nil {
		return fmt.Errorf("finding child pid: %w", err)
	}

	clog.FromContext(ctx).Infof("got pid: %d", pid)

	pod := &pod{
		pid: pid,
		cmd: cmd,
	}

	if !cfg.Capabilities.Networking {
		return fmt.Errorf("https://github.com/containers/bubblewrap/issues/61")
	}

	cfg.PodID = strconv.Itoa(pid)
	bw.pods[cfg.PodID] = pod

	return nil
}

// TerminatePod terminates a pod if necessary.  Not implemented
// for Bubblewrap runners.
func (bw *bubblewrap) TerminatePod(ctx context.Context, cfg *Config) error {
	pod, ok := bw.pods[cfg.PodID]
	if !ok {
		return fmt.Errorf("pod %q not found", cfg.PodID)
	}

	if err := pod.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("killing %d: %w", pod.cmd.Process.Pid, err)
	}

	err := pod.cmd.Wait()
	if err == nil {
		return nil
	}

	var eerr *exec.ExitError
	if !errors.As(err, &eerr) {
		return err
	}

	state := pod.cmd.ProcessState
	if state == nil {
		return err
	}

	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok {
		return err
	}

	if status.Signaled() && status.Signal() == syscall.SIGKILL {
		// We killed it!
		return nil
	}

	// Not clear if we killed it, just return the original error (it's non-fatal anyway).
	return err
}

// WorkspaceTar implements Runner
// This is a noop for Bubblewrap, which uses bind-mounts to manage the workspace
func (bw *bubblewrap) WorkspaceTar(ctx context.Context, cfg *Config) (io.ReadCloser, error) {
	return nil, nil
}

type bubblewrapOCILoader struct{}

func (b bubblewrapOCILoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	_, span := otel.Tracer("melange").Start(ctx, "bubblewrap.LoadImage")
	defer span.End()

	// bubblewrap does not have the idea of container images or layers or such, just
	// straight out chroot, so we create the guest dir
	guestDir, err := os.MkdirTemp("", "melange-guest-*")
	if err != nil {
		return ref, fmt.Errorf("failed to create guest dir: %w", err)
	}
	rc, err := layer.Uncompressed()
	if err != nil {
		return ref, fmt.Errorf("failed to read layer tarball: %w", err)
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		fullname := filepath.Join(guestDir, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(fullname, hdr.FileInfo().Mode().Perm()); err != nil {
				return ref, fmt.Errorf("failed to create directory %s: %w", fullname, err)
			}
			continue
		case tar.TypeReg:
			f, err := os.OpenFile(fullname, os.O_CREATE|os.O_WRONLY, hdr.FileInfo().Mode().Perm())
			if err != nil {
				return ref, fmt.Errorf("failed to create file %s: %w", fullname, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				return ref, fmt.Errorf("failed to copy file %s: %w", fullname, err)
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, filepath.Join(guestDir, hdr.Name)); err != nil {
				return ref, fmt.Errorf("failed to create symlink %s: %w", fullname, err)
			}
		case tar.TypeLink:
			if err := os.Link(filepath.Join(guestDir, hdr.Linkname), filepath.Join(guestDir, hdr.Name)); err != nil {
				return ref, fmt.Errorf("failed to create hardlink %s: %w", fullname, err)
			}
		default:
			// TODO: Is this correct? We are loading these into the directory, so character devices and such
			// do not really matter to us, but maybe they should?
			continue
		}
	}
	return guestDir, nil
}

func (b bubblewrapOCILoader) RemoveImage(ctx context.Context, ref string) error {
	clog.FromContext(ctx).Infof("removing image path %s", ref)
	return os.RemoveAll(ref)
}

func getLeafPID(root int) (int, error) {
	childrenFile := fmt.Sprintf("/proc/%d/task/%d/children", root, root)
	data, err := os.ReadFile(childrenFile)
	if err != nil {
		return 0, err
	}

	childrenStr := strings.TrimSpace(string(data))
	if childrenStr == "" {
		return root, nil
	}

	childrenStrSlice := strings.Split(childrenStr, " ")

	if len(childrenStrSlice) > 1 {
		return 0, fmt.Errorf("more than one child found for process %d", root)
	}

	childPID, err := strconv.Atoi(childrenStrSlice[0])
	if err != nil {
		return 0, err
	}

	return getLeafPID(childPID)
}
