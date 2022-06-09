package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/nix-community/go-nix/pkg/derivation"
	"github.com/nix-community/go-nix/pkg/nixpath"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

const sandboxBuildDir = "/build"

const ociRuntime = "runc"

var envEscaper = strings.NewReplacer(
	"\\\\", "\\",
	"\\n", "\n",
	"\\r", "\r",
	"\\t", "\t",
	"\\\"", "\"",
)

var sandboxPaths = map[string]string{
	"/bin/sh": "/nix/store/kas8m76rr10h78hfl3yk66akdi08bkf9-busybox-static-x86_64-unknown-linux-musl-1.35.0/bin/busybox",
}

type OCIBuild struct {
	cmd    *exec.Cmd
	tmpDir string // Path to mutable store that build outputs to
}

func NewOCIBuild(ctx context.Context, drv *derivation.Derivation, buildInputs []string) (*OCIBuild, error) {
	// TODO: Call os.MkdirTemp
	tmpDir, err := filepath.Abs("./tmp")
	if err != nil {
		return nil, err
	}

	rootless := true
	buildDir := filepath.Join(tmpDir, "builddir")
	rootFsDir := filepath.Join(tmpDir, "rootfs")

	// Create required file structure
	{
		err := os.Mkdir(tmpDir, 0700)
		if err != nil {
			return nil, err
		}

		err = os.MkdirAll(filepath.Join(tmpDir, nixpath.StoreDir), 0700)
		if err != nil {
			return nil, err
		}

		err = os.Mkdir(buildDir, 0700)
		if err != nil {
			return nil, err
		}

		err = os.Mkdir(rootFsDir, 0700)
		if err != nil {
			return nil, err
		}

		err = os.Mkdir(filepath.Join(rootFsDir, "etc"), 0700)
		if err != nil {
			return nil, err
		}

		// /etc/passwd
		{
			f, err := os.Create(filepath.Join(rootFsDir, "etc", "passwd"))
			if err != nil {
				return nil, err
			}

			f.Write([]byte("root:x:0:0:Nix build user:0:/noshell\n"))
			f.Write([]byte("nixbld:x:1000:100:Nix build user:/build:/noshell"))
			f.Write([]byte("nobody:x:65534:65534:Nobody:/:/noshell\n"))

			f.Close()
		}

		// /etc/group
		{
			f, err := os.Create(filepath.Join(rootFsDir, "etc", "group"))
			if err != nil {
				return nil, err
			}

			f.Write([]byte("root:x:0:\n"))
			f.Write([]byte("nixbld:!:100:"))
			f.Write([]byte("nogroup:x:65534:\n"))

			f.Close()
		}
	}

	caps := []string{"CAP_AUDIT_WRITE", "CAP_KILL"}
	if rootless {
		caps = []string{
			"CAP_AUDIT_WRITE",
			"CAP_CHOWN",
			"CAP_DAC_OVERRIDE",
			"CAP_FOWNER",
			"CAP_FSETID",
			"CAP_KILL",
			"CAP_MKNOD",
			"CAP_NET_BIND_SERVICE",
			"CAP_NET_RAW",
			"CAP_SETFCAP",
			"CAP_SETGID",
			"CAP_SETPCAP",
			"CAP_SETUID",
			"CAP_SYS_CHROOT",
		}
	}

	// Create OCI spec
	spec := &oci.Spec{
		Version: oci.Version,

		Process: &oci.Process{
			Terminal: false,
			User: oci.User{
				UID: 0,
				GID: 0,
			},
			Cwd: sandboxBuildDir,
			Capabilities: &oci.LinuxCapabilities{
				Bounding:    caps,
				Effective:   caps,
				Inheritable: caps,
				Permitted:   caps,
				Ambient:     caps,
			},
			Rlimits: []oci.POSIXRlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: 1024,
					Soft: 1024,
				},
			},
			NoNewPrivileges: true,
		},

		Linux: &oci.Linux{
			Namespaces: []oci.LinuxNamespace{
				{
					Type: oci.PIDNamespace,
				},
				{
					Type: oci.IPCNamespace,
				},
				{
					Type: oci.UTSNamespace,
				},
				{
					Type: oci.MountNamespace,
				},
				{
					Type: oci.CgroupNamespace,
				},
			},
			MaskedPaths: []string{
				"/proc/kcore",
				"/proc/latency_stats",
				"/proc/timer_list",
				"/proc/timer_stats",
				"/proc/sched_debug",
				"/sys/firmware",
			},
			ReadonlyPaths: []string{
				"/proc/asound",
				"/proc/bus",
				"/proc/fs",
				"/proc/irq",
				"/proc/sys",
				"/proc/sysrq-trigger",
			},
		},

		Root: &oci.Root{
			Path:     rootFsDir,
			Readonly: true,
		},

		Hostname: "localhost",

		Mounts: []oci.Mount{
			{
				Destination: "/proc",
				Type:        "proc",
				Source:      "proc",
			},
			{
				Destination: "/dev",
				Type:        "tmpfs",
				Source:      "tmpfs",
				Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
			},
			{
				Destination: "/dev/pts",
				Type:        "devpts",
				Source:      "devpts",
				Options: func() []string {
					options := []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}
					if rootless {
						return options
					} else {
						return append(options, "gid=5")
					}
				}(),
			},
			{
				Destination: "/dev/shm",
				Type:        "tmpfs",
				Source:      "shm",
				Options:     []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
			},
			{
				Destination: "/dev/mqueue",
				Type:        "mqueue",
				Source:      "mqueue",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
			{
				Destination: "/sys",
				Type:        "none",
				Source:      "/sys",
				Options:     []string{"rbind", "nosuid", "noexec", "nodev", "ro"},
			},
			{
				Destination: "/sys/fs/cgroup",
				Type:        "cgroup",
				Source:      "cgroup",
				Options:     []string{"nosuid", "noexec", "nodev", "relatime", "ro"},
			},
			{
				Destination: "/tmp",
				Type:        "tmpfs",
				Source:      "tmpfs",
				Options:     []string{"nosuid", "noatime", "mode=700"},
			},

			// Mount /build, the scratch build directory
			{
				Destination: "/build",
				Type:        "none",
				Source:      buildDir,
				Options:     []string{"rbind", "rw"},
			},

			// # Mount /nix/store
			// It might seem counterintuitive that we mount the entire store
			// as writable, but it is what Nix has always done and scripts are expected to create
			// their outputs themselves.
			// If we created the output and bind mounted it there would be no way to detect if
			// a build fails to create one or more of it's outputs.
			{
				Destination: nixpath.StoreDir,
				Type:        "none",
				Source:      filepath.Join(tmpDir, nixpath.StoreDir),
				Options:     []string{"rbind", "rw"},
			},
		},
	}

	// Set build command
	spec.Process.Args = append(append(spec.Process.Args, drv.Builder), drv.Arguments...)

	// Populate env vars
	{
		spec.Process.Env = append(
			spec.Process.Env,
			"TMPDIR="+sandboxBuildDir,
			"TEMPDIR="+sandboxBuildDir,
			"TMP="+sandboxBuildDir,
			"TEMP="+sandboxBuildDir,
			"TERM=xterm-256color",
			"HOME=/homeless-shelter",
			"NIX_BUILD_TOP="+sandboxBuildDir,
			"NIX_BUILD_CORES=1",
			"NIX_LOG_FD=2",
			"NIX_STORE="+nixpath.StoreDir,
		)

		for key, value := range drv.Env {
			spec.Process.Env = append(spec.Process.Env, key+"="+envEscaper.Replace(value))
		}
	}

	// Allow user namespaces for rootless mode
	if rootless {
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, oci.LinuxNamespace{
			Type: oci.UserNamespace,
		})
	}

	// Add mappings for rootless mode
	// TODO: Figure out why uid/gid mappings are not working with crun
	if rootless && ociRuntime != "crun" {
		spec.Linux.GIDMappings = []oci.LinuxIDMapping{
			{
				ContainerID: 0,
				HostID:      100,
				Size:        1,
			},
			{
				ContainerID: 1,
				HostID:      100000,
				Size:        65536,
			},
		}
		spec.Linux.UIDMappings = []oci.LinuxIDMapping{
			{
				ContainerID: 0,
				HostID:      1000,
				Size:        1,
			},
			{
				ContainerID: 1,
				HostID:      100000,
				Size:        65536,
			},
		}
	}

	// If fixed output allow networking
	if fixed := drv.GetFixedOutput(); fixed != nil {

		for _, file := range []string{"/etc/resolv.conf", "/etc/services", "/etc/hosts"} {
			if !pathExists(file) {
				continue
			}

			spec.Mounts = append(spec.Mounts, oci.Mount{
				Destination: file,
				Type:        "none",
				Source:      file,
				Options:     []string{"bind", "rprivate"},
			})
		}

	} else {
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, oci.LinuxNamespace{
			Type: oci.NetworkNamespace,
		})
	}

	// Mount sandbox paths (such as /bin/sh)
	for destination, source := range sandboxPaths {
		spec.Mounts = append(spec.Mounts, oci.Mount{
			Destination: destination,
			Type:        "none",
			Source:      source,
			Options:     []string{"rbind", "ro"},
		})
	}

	// Mount input sources
	for _, inputSource := range drv.InputSources {
		spec.Mounts = append(spec.Mounts, oci.Mount{
			Destination: inputSource,
			Type:        "none",
			Source:      inputSource,
			Options:     []string{"rbind", "ro"},
		})
	}

	// Mount store paths of dependencies
	for _, buildInput := range buildInputs {
		spec.Mounts = append(spec.Mounts, oci.Mount{
			Destination: buildInput,
			Type:        "none",
			Source:      buildInput,
			Options:     []string{"rbind", "ro"},
		})
	}

	// # Platform unhandled (for now)
	// drv.pop("system")

	// Write out config.json
	{
		f, err := os.Create(filepath.Join(tmpDir, "config.json"))
		if err != nil {
			return nil, err
		}

		b, err := json.Marshal(spec)
		if err != nil {
			return nil, err
		}

		_, err = f.Write(b)
		if err != nil {
			return nil, err
		}
	}

	containerUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("error creating container uuid: %w", err)
	}

	cmd := exec.CommandContext(ctx, ociRuntime, "run", containerUUID.String())
	{
		cmd.Dir = tmpDir
		cmd.Env = os.Environ() // TODO: Create environment from scratch
	}

	return &OCIBuild{
		tmpDir: tmpDir,
		cmd:    cmd,
	}, nil
}

func (o *OCIBuild) SetStderr(stderr io.Writer) error {
	o.cmd.Stderr = stderr

	return nil
}

func (o *OCIBuild) SetStdout(stdout io.Writer) error {
	o.cmd.Stdout = stdout

	return nil
}

func (o *OCIBuild) Start() error {
	return o.cmd.Start()
}

func (o *OCIBuild) Wait() error {
	return o.cmd.Wait()
}

func (o *OCIBuild) Close() error {
	// TODO: Reinstate RemoveAll
	// return os.RemoveAll(o.tmpDir)
	return nil
}
