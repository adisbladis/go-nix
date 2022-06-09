package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nix-community/go-nix/pkg/derivation"
	"github.com/nix-community/go-nix/pkg/derivation/store"
	"github.com/nix-community/go-nix/pkg/nar"
	"github.com/nix-community/go-nix/pkg/nixpath"
	"github.com/nix-community/go-nix/pkg/nixpath/references"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

var envEscaper = strings.NewReplacer(
	"\\\\", "\\",
	"\\n", "\n",
	"\\r", "\r",
	"\\t", "\t",
	"\\\"", "\"",
)

var sandboxBuildDir = "/build"
var sandboxPaths = map[string]string{
	"/bin/sh": "/nix/store/3dh3y53aw3a3fyanjsjjj182rphq4j6l-busybox-static-x86_64-unknown-linux-musl-1.35.0/bin/busybox",
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		panic(err)
	}
}

// Environment from a minimal derivation:
// HOME=/homeless-shelter
// NIX_BUILD_CORES=0
// NIX_BUILD_TOP=/build
// NIX_LOG_FD=2
// NIX_STORE=/nix/store
// PATH=/path-not-set
// PWD=/build
// TEMP=/build
// TEMPDIR=/build
// TERM=xterm-256color
// TMP=/build
// TMPDIR=/build
// builder=/nix/store/jqlrr5w3a4f7b15njdk40930cns1jskm-env
// name=env
// out=/nix/store/vw88m43ca06y5y9a3z4d39973yq0x6xb-env
// system=x86_64-linux

// findBuildInputs - Temporary stub function
func findBuildInputs(store derivation.Store, drv *derivation.Derivation) ([]string, error) {
	var buildInputs []string

	for drvPath, outputNames := range drv.InputDerivations {
		inputDrv, err := store.Get(drvPath)
		if err != nil {
			return nil, err
		}

		for _, outputName := range outputNames {
			cmd := exec.Command("nix-store", "-qR", inputDrv.Outputs[outputName].Path)

			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return nil, err
			}

			scanner := bufio.NewScanner(stdout)

			err = cmd.Start()
			if err != nil {
				return nil, err
			}

			for scanner.Scan() {
				buildInput := scanner.Text()
				buildInputs = append(buildInputs, buildInput)
			}

			cmd.Wait()
		}
	}

	return buildInputs, nil
}

func main() {

	tmpDir := "tmp"

	rootless := true
	buildDir := filepath.Join(tmpDir, "builddir")
	rootFsDir := filepath.Join(tmpDir, "rootfs")

	var drv *derivation.Derivation
	{
		// drvPath := "/nix/store/8cgdj1wfb1z1wpychr67czb2v6i9ka91-hello-2.12.drv"

		// drvPath := "/nix/store/5zhfmj5j8b326g6pxlc4ky6i2il20avp-jq-1.6.drv"

		drvPath := "/nix/store/m10f6vhdqicbis1zijfn91xhk51zbx56-source.drv"

		// drvPath := "/nix/store/9czdndfayi61yywyxfjyliskaribxz2s-testhest.drv"

		// drvPath := "/nix/store/lbpxm2q7j053b243dfxlg1v7bsjfqw9s-element-desktop-1.10.13.drv"

		f, err := os.Open(drvPath)
		if err != nil {
			panic(err)
		}

		drv, err = derivation.ReadDerivation(f)
		if err != nil {
			panic(err)
		}
	}

	store := store.NewFSStoreNixStore()

	buildInputs, err := findBuildInputs(store, drv)
	if err != nil {
		panic(err)
	}

	// TODO: Factor out
	{
		err := os.Mkdir(tmpDir, 0700)
		if err != nil {
			panic(err)
		}

		err = os.MkdirAll(filepath.Join(tmpDir, nixpath.StoreDir), 0700)
		if err != nil {
			panic(err)
		}

		err = os.Mkdir(buildDir, 0700)
		if err != nil {
			panic(err)
		}

		err = os.Mkdir(rootFsDir, 0700)
		if err != nil {
			panic(err)
		}

		err = os.Mkdir(filepath.Join(rootFsDir, "etc"), 0700)
		if err != nil {
			panic(err)
		}

		// /etc/passwd
		{
			f, err := os.Create(filepath.Join(rootFsDir, "etc", "passwd"))
			if err != nil {
				panic(err)
			}

			f.Write([]byte("root:x:0:0:Nix build user:0:/noshell\n"))
			f.Write([]byte("nobody:x:65534:65534:Nobody:/:/noshell\n"))

			f.Close()
		}

		// /etc/group
		{
			f, err := os.Create(filepath.Join(rootFsDir, "etc", "group"))
			if err != nil {
				panic(err)
			}

			f.Write([]byte("root:x:0:\n"))
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

	spec := &oci.Spec{
		Version: oci.Version,

		Process: &oci.Process{
			Terminal: true,
			User: oci.User{
				UID: 1000,
				GID: 100,
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
	if rootless {
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

	{
		// Mount store paths of dependencies
		for _, buildInput := range buildInputs {
			spec.Mounts = append(spec.Mounts, oci.Mount{
				Destination: buildInput,
				Type:        "none",
				Source:      buildInput,
				Options:     []string{"rbind", "ro"},
			})
		}
	}

	// # Platform unhandled (for now)
	// drv.pop("system")

	// Write out config.json
	{
		f, err := os.Create("./config.json")
		if err != nil {
			panic(err)
		}

		b, err := json.Marshal(spec)
		if err != nil {
			panic(err)
		}

		_, err = f.Write(b)
		if err != nil {
			panic(err)
		}
	}

	// Run the build
	{
		uuid := "aab1c5a9-5851-4b91-b2d5-236f95ca2af9"
		cmd := exec.Command("runc", "run", uuid)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		cmd.Env = os.Environ() // TODO: Create environment from scratch

		fmt.Println(cmd)

		err = cmd.Start()
		if err != nil {
			panic(err)
		}

		err = cmd.Wait()
		if err != nil {
			panic(err)
		}
	}

	// Scan for references
	fmt.Println("Scanning for references")
	{
		start := time.Now()

		outputReferences := make(map[string][]string)

		for _, o := range drv.Outputs {
			path := filepath.Join(tmpDir, o.Path)

			scanner, err := references.NewReferenceScanner(buildInputs)
			if err != nil {
				panic(err)
			}

			err = nar.DumpPath(scanner, path)
			if err != nil {
				panic(err)
			}

			outputReferences[o.Path] = scanner.References()
		}

		duration := time.Since(start)
		fmt.Println(duration)
	}
	fmt.Println("Done scanning for references")
}
