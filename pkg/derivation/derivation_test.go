package derivation_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nix-community/go-nix/pkg/derivation"
	"github.com/nix-community/go-nix/pkg/nixpath"
	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	cases := []struct {
		Title          string
		DerivationFile string
		Output         *derivation.Output
		Platform       string
		Builder        string
		EnvVars        []derivation.Env
	}{
		{
			"Basic",
			"m5j1yp47lw1psd9n6bzina1167abbprr-bash44-023.drv",
			//			"basic.drv",
			&derivation.Output{
				Name:          "out",
				Path:          "/nix/store/x9cyj78gzd1wjf0xsiad1pa3ricbj566-bash44-023",
				HashAlgorithm: "sha256",
				Hash:          "4fec236f3fbd3d0c47b893fdfa9122142a474f6ef66c20ffb6c0f4864dd591b6",
			},
			"builtin",
			"builtin:fetchurl",
			[]derivation.Env{
				{
					Key:   "builder",
					Value: "builtin:fetchurl",
				},
				{
					Key: "executable",
				},
				{
					Key:   "impureEnvVars",
					Value: "http_proxy https_proxy ftp_proxy all_proxy no_proxy",
				},
				{
					Key:   "name",
					Value: "bash44-023",
				},
				{
					Key:   "out",
					Value: "/nix/store/x9cyj78gzd1wjf0xsiad1pa3ricbj566-bash44-023",
				},
				{
					Key:   "outputHash",
					Value: "1dlism6qdx60nvzj0v7ndr7lfahl4a8zmzckp13hqgdx7xpj7v2g",
				},
				{
					Key:   "outputHashAlgo",
					Value: "sha256",
				},
				{
					Key:   "outputHashMode",
					Value: "flat",
				},
				{
					Key:   "preferLocalBuild",
					Value: "1",
				},
				{
					Key:   "system",
					Value: "builtin",
				},
				{
					Key: "unpack",
				},
				{
					Key:   "url",
					Value: "https://ftpmirror.gnu.org/bash/bash-4.4-patches/bash44-023",
				},
				{
					Key:   "urls",
					Value: "https://ftpmirror.gnu.org/bash/bash-4.4-patches/bash44-023",
				},
			},
		},
	}

	t.Run("ParseDerivations", func(t *testing.T) {
		for _, c := range cases {
			t.Run(c.Title, func(t *testing.T) {
				derivationFile, err := os.Open("../../test/testdata/" + c.DerivationFile)
				if err != nil {
					panic(err)
				}

				drv, err := derivation.ReadDerivation(derivationFile)
				if err != nil {
					panic(err)
				}
				// repr.Println(drv, repr.Indent("  "), repr.OmitEmpty(true))
				assert.Equal(t, &drv.Outputs[0], c.Output)
				assert.Equal(t, drv.Builder, c.Builder)
				assert.Equal(t, drv.EnvVars, c.EnvVars)
			})
		}
	})
}

func TestEncoder(t *testing.T) {
	cases := []struct {
		Title          string
		DerivationFile string
	}{
		{
			Title:          "Basic",
			DerivationFile: "m5j1yp47lw1psd9n6bzina1167abbprr-bash44-023.drv",
		},
		{
			Title:          "Complex",
			DerivationFile: "cl5fr6hlr6hdqza2vgb9qqy5s26wls8i-jq-1.6.drv",
		},
		{
			Title:          "Builder Nixpath",
			DerivationFile: "0zhkga32apid60mm7nh92z2970im5837-bootstrap-tools.drv",
		},
		{
			Title:          "fixed-sha256",
			DerivationFile: "0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv",
		},
		{
			// Has a single fixed-output dependency
			Title:          "simple-sha256",
			DerivationFile: "4wvvbi4jwn0prsdxb7vs673qa5h9gr7x-foo.drv",
		},
		{
			Title:          "fixed-sha1",
			DerivationFile: "ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv",
		},
		{
			// Has a single fixed-output dependency
			Title:          "simple-sha1",
			DerivationFile: "ch49594n9avinrf8ip0aslidkc4lxkqv-foo.drv",
		},
		{
			Title:          "has-file-dependency",
			DerivationFile: "385bniikgs469345jfsbw24kjfhxrsi0-foo-file.drv",
		},
		{
			Title:          "has-file-and-drv-dependency",
			DerivationFile: "z8dajq053b2bxc3ncqp8p8y3nfwafh3p-foo-file.drv",
		},
	}

	t.Run("WriteDerivation", func(t *testing.T) {
		for _, c := range cases {
			t.Run(c.Title, func(t *testing.T) {
				derivationFile, err := os.Open("../../test/testdata/" + c.DerivationFile)
				if err != nil {
					panic(err)
				}

				derivationBytes, err := io.ReadAll(derivationFile)
				if err != nil {
					panic(err)
				}

				drv, err := derivation.ReadDerivation(bytes.NewReader(derivationBytes))
				if err != nil {
					panic(err)
				}

				var sb strings.Builder
				err = drv.WriteDerivation(&sb)
				if err != nil {
					panic(err)
				}

				assert.Equal(t, sb.String(), string(derivationBytes))
			})
		}
	})
}

func TestOutputs(t *testing.T) {
	drv := &derivation.Derivation{
		Outputs: []derivation.Output{
			{
				Name: "foo",
				Path: "dummy",
			},
			{
				Name: "bar",
				Path: "dummy2",
			},
		},
	}

	t.Run("String", func(t *testing.T) {
		assert.Equal(t, "dummy", drv.String())
	})
}

func TestValidate(t *testing.T) {
	getDerivation := func() *derivation.Derivation {
		derivationFile, err := os.Open("../../test/testdata/cl5fr6hlr6hdqza2vgb9qqy5s26wls8i-jq-1.6.drv")
		if err != nil {
			panic(err)
		}

		drv, err := derivation.ReadDerivation(derivationFile)
		if err != nil {
			panic(err)
		}

		return drv
	}

	t.Run("InvalidOutput", func(t *testing.T) {
		t.Run("NoOutputsAtAll", func(t *testing.T) {
			drv := getDerivation()

			drv.Outputs = []derivation.Output{}

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"at least one output must be defined",
				"error should complain about missing outputs",
			)
		})

		t.Run("NoOutputName", func(t *testing.T) {
			drv := getDerivation()

			drv.Outputs[0].Name = ""

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"empty output name",
				"error should complain about missing output name",
			)
		})

		t.Run("InvalidPath", func(t *testing.T) {
			drv := getDerivation()

			drv.Outputs[0].Path = "invalidPath"

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"unable to parse path",
				"error should complain about path syntax",
			)
		})

		t.Run("InvalidOrder", func(t *testing.T) {
			drv := getDerivation()

			drv.Outputs[0].Name = "foo"

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"invalid output order",
				"error should complain about output order",
			)
		})
	})

	t.Run("InvalidDerivation", func(t *testing.T) {
		t.Run("InvalidPath", func(t *testing.T) {
			drv := getDerivation()

			drv.InputDerivations[0].Path = "bar"

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"unable to parse path",
				"error should complain about path syntax",
			)
		})

		t.Run("InvalidOrder", func(t *testing.T) {
			drv := getDerivation()

			drv.InputDerivations[0].Path = "/nix/store/5k1sfc5qmzb93addcjxxnqcd5bpf2wlz-hook.drv"
			drv.InputDerivations[1].Path = "/nix/store/4k1sfc5qmzb93addcjxxnqcd5bpf2wlz-hook.drv"

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"invalid input derivation order",
				"error should complain about ordering",
			)
		})
	})

	t.Run("InvalidInputSource", func(t *testing.T) {
		t.Run("InvalidPath", func(t *testing.T) {
			drv := getDerivation()

			drv.InputSources[0] = "baz"

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"unable to parse path",
				"error should complain about path syntax",
			)
		})

		t.Run("InvalidOrder", func(t *testing.T) {
			drv := getDerivation()

			drv.InputSources[0] = "/nix/store/5k1sfc5qmzb93addcjxxnqcd5bpf2wlz-hook.drv"
			drv.InputSources = append(drv.InputSources, "/nix/store/4k1sfc5qmzb93addcjxxnqcd5bpf2wlz-hook.drv")

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"invalid input source order",
				"error should complain about ordering",
			)
		})
	})

	t.Run("MissingPlatform", func(t *testing.T) {
		drv := getDerivation()

		drv.Platform = ""

		err := drv.Validate()
		assert.Error(t, err)

		assert.Containsf(
			t,
			err.Error(),
			"required attribute 'platform' missing",
			"error should complain about missing platform",
		)
	})

	t.Run("MissingBuilder", func(t *testing.T) {
		drv := getDerivation()

		drv.Builder = ""

		err := drv.Validate()
		assert.Error(t, err)

		assert.Containsf(
			t,
			err.Error(),
			"required attribute 'builder' missing",
			"error should complain about missing builder",
		)
	})

	t.Run("InvalidEnvVar", func(t *testing.T) {
		t.Run("InvalidOrder", func(t *testing.T) {
			drv := getDerivation()

			drv.EnvVars[0].Key = "foo"
			drv.EnvVars[1].Key = "bar"

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"invalid env var order",
				"error should complain about ordering",
			)
		})

		t.Run("EmpyEnvVar", func(t *testing.T) {
			drv := getDerivation()

			drv.EnvVars[0].Key = ""

			err := drv.Validate()
			assert.Error(t, err)

			assert.Containsf(
				t,
				err.Error(),
				"empty environment variable key",
				"error should complain about empty key",
			)
		})
	})
}

type testFSStore struct {
	// Use the FS kv store for better test coverage of stores
	store *derivation.FSKVStore
}

func (kv *testFSStore) Get(key string) ([]byte, error) {
	path := filepath.Join("../../test/testdata/", strings.TrimPrefix(key, nixpath.StoreDir+"/"))

	return kv.store.Get(path)
}

func (kv *testFSStore) Set(key string, value []byte) error {
	return kv.store.Set(key, value)
}

func TestDrvPath(t *testing.T) {
	cases := []struct {
		Title          string
		DerivationFile string
	}{
		{
			Title:          "fixed-sha256",
			DerivationFile: "0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv",
		},
		{
			// Has a single fixed-output dependency
			Title:          "simple-sha256",
			DerivationFile: "4wvvbi4jwn0prsdxb7vs673qa5h9gr7x-foo.drv",
		},
		{
			Title:          "fixed-sha1",
			DerivationFile: "ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv",
		},
		{
			// Has a single fixed-output dependency
			Title:          "simple-sha1",
			DerivationFile: "ch49594n9avinrf8ip0aslidkc4lxkqv-foo.drv",
		},
		{
			Title:          "has-file-dependency",
			DerivationFile: "385bniikgs469345jfsbw24kjfhxrsi0-foo-file.drv",
		},
		{
			Title:          "has-file-and-drv-dependency",
			DerivationFile: "z8dajq053b2bxc3ncqp8p8y3nfwafh3p-foo-file.drv",
		},
	}

	for _, c := range cases {
		t.Run(c.Title, func(t *testing.T) {
			derivationFile, err := os.Open("../../test/testdata/" + c.DerivationFile)
			if err != nil {
				panic(err)
			}

			derivationBytes, err := io.ReadAll(derivationFile)
			if err != nil {
				panic(err)
			}

			drv, err := derivation.ReadDerivation(bytes.NewReader(derivationBytes))
			if err != nil {
				panic(err)
			}

			drvPath, err := drv.DrvPath()
			if err != nil {
				panic(err)
			}

			assert.Equal(t, filepath.Join(nixpath.StoreDir, c.DerivationFile), drvPath)
		})
	}
}

func TestOutputPaths(t *testing.T) {
	cases := []struct {
		Title          string
		DerivationFile string
	}{
		{
			Title:          "fixed-sha256",
			DerivationFile: "/nix/store/0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv",
		},
		{
			// Has a single fixed-output dependency
			Title:          "simple-sha256",
			DerivationFile: "/nix/store/4wvvbi4jwn0prsdxb7vs673qa5h9gr7x-foo.drv",
		},
		{
			Title:          "fixed-sha1",
			DerivationFile: "/nix/store/ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv",
		},
		{
			// Has a single fixed-output dependency
			Title:          "simple-sha1",
			DerivationFile: "/nix/store/ch49594n9avinrf8ip0aslidkc4lxkqv-foo.drv",
		},
	}

	store := &testFSStore{
		store: &derivation.FSKVStore{},
	}

	for _, c := range cases {
		t.Run(filepath.Base(c.Title), func(t *testing.T) {
			derivationBytes, err := store.Get(c.DerivationFile)
			if err != nil {
				panic(err)
			}

			drv, err := derivation.ReadDerivation(bytes.NewReader(derivationBytes))
			if err != nil {
				panic(err)
			}

			outputs, err := drv.OutputPaths(store)
			if err != nil {
				panic(err)
			}

			for _, o := range drv.Outputs {
				t.Run(o.Name, func(t *testing.T) {
					assert.Equal(t, o.Path, outputs[o.Name])
				})
			}
		})
	}
}
