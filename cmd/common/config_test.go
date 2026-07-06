package common

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	yaml "gopkg.in/yaml.v3"
)

const configTestDir = "pkg/resources/test"

// We should load config correctly.
func TestLoadConfig(t *testing.T) {
	t.Parallel()

	conf := LoadConfig(filepath.Join(configTestDir, "config-test.yml"))

	home, _ := os.UserHomeDir()
	assert.Equal(t, filepath.Join(home, "somewhere/else"), conf.CacheDir)
	assert.Equal(t, "warn", conf.LogLevel)
	assert.Equal(t, Duration(720*time.Hour), conf.CacheMaxAge)
	assert.Equal(t, 720*time.Hour, conf.CacheMaxAge.AsDuration())
}

func TestConfigMerge(t *testing.T) {
	t.Parallel()

	conf := LoadConfig(filepath.Join(configTestDir, "config-test-merge.yml"))

	assert.Equal(t, "debug", conf.LogLevel)
	assert.Equal(t, "/some/directory", conf.CacheDir)
}

// We should come up with the defaults if there is no config file.
func TestLoadNonexistentConfig(t *testing.T) {
	t.Parallel()

	conf := LoadConfig(filepath.Join(configTestDir, "does-not-exist.yml"))

	home, _ := os.UserHomeDir()
	assert.Equal(t, filepath.Join(home, ".cache/onedriver"), conf.CacheDir)
	assert.Equal(t, "debug", conf.LogLevel)
}

func TestWriteConfig(t *testing.T) {
	t.Parallel()
	conf := LoadConfig(filepath.Join(configTestDir, "config-test.yml"))
	assert.NoError(t, conf.WriteConfig("tmp/nested/config.yml"))
}

// Duration strings from YAML should be correctly parsed via time.ParseDuration.
func TestCacheMaxAgeParse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		yaml     string
		expected time.Duration
	}{
		{"cacheMaxAge: 720h", 720 * time.Hour},
		{"cacheMaxAge: 24h", 24 * time.Hour},
		{"cacheMaxAge: 5m", 5 * time.Minute},
		{"cacheMaxAge: 30s", 30 * time.Second},
		{"cacheMaxAge: 0", 0},
	}
	for _, c := range cases {
		conf := &Config{}
		err := yaml.Unmarshal([]byte(c.yaml), conf)
		assert.NoError(t, err, "failed to parse: %s", c.yaml)
		assert.Equal(t, Duration(c.expected), conf.CacheMaxAge,
			"unexpected duration for: %s", c.yaml)
	}
}

// Omitting cacheMaxAge from the YAML should leave it at zero (disabled).
func TestCacheMaxAgeDefault(t *testing.T) {
	t.Parallel()

	conf := &Config{}
	err := yaml.Unmarshal([]byte("log: info\n"), conf)
	assert.NoError(t, err)
	assert.Equal(t, Duration(0), conf.CacheMaxAge)
}

// Invalid duration strings must reject.
func TestCacheMaxAgeInvalid(t *testing.T) {
	t.Parallel()

	err := yaml.Unmarshal([]byte("cacheMaxAge: notaduration"), &Config{})
	assert.Error(t, err)
}
