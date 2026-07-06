package common

import (
	"os"
	"path/filepath"
	"time"

	"dario.cat/mergo"
	"github.com/jstaf/onedriver/fs/graph"
	"github.com/jstaf/onedriver/ui"
	"github.com/rs/zerolog/log"
	yaml "gopkg.in/yaml.v3"
)

// Duration is a time.Duration wrapper that supports YAML (un)marshaling
// from Go duration strings like "720h", "5m", "30s".
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler for YAML parsing.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// MarshalText implements encoding.TextMarshaler for YAML serialization.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// AsDuration returns the underlying time.Duration.
func (d Duration) AsDuration() time.Duration {
	return time.Duration(d)
}

type Config struct {
	CacheDir         string   `yaml:"cacheDir"`
	LogLevel         string   `yaml:"log"`
	CacheMaxAge      Duration `yaml:"cacheMaxAge"`
	graph.AuthConfig `yaml:"auth"`
}

// DefaultConfigPath returns the default config location for onedriver
func DefaultConfigPath() string {
	confDir, err := os.UserConfigDir()
	if err != nil {
		log.Error().Err(err).Msg("Could not determine configuration directory.")
	}
	return filepath.Join(confDir, "onedriver/config.yml")
}

// LoadConfig is the primary way of loading onedriver's config
func LoadConfig(path string) *Config {
	xdgCacheDir, _ := os.UserCacheDir()
	defaults := Config{
		CacheDir: filepath.Join(xdgCacheDir, "onedriver"),
		LogLevel: "debug",
	}

	conf, err := os.ReadFile(path)
	if err != nil {
		log.Warn().
			Err(err).
			Str("path", path).
			Msg("Configuration file not found, using defaults.")
		return &defaults
	}
	config := &Config{}
	if err = yaml.Unmarshal(conf, config); err != nil {
		log.Error().
			Err(err).
			Str("path", path).
			Msg("Could not parse configuration file, using defaults.")
	}
	if err = mergo.Merge(config, defaults); err != nil {
		log.Error().
			Err(err).
			Str("path", path).
			Msg("Could not merge configuration file with defaults, using defaults only.")
	}

	config.CacheDir = ui.UnescapeHome(config.CacheDir)
	return config
}

// Write config to a file
func (c Config) WriteConfig(path string) error {
	out, err := yaml.Marshal(c)
	if err != nil {
		log.Error().Err(err).Msg("Could not marshal config!")
		return err
	}
	os.MkdirAll(filepath.Dir(path), 0700)
	err = os.WriteFile(path, out, 0600)
	if err != nil {
		log.Error().Err(err).Msg("Could not write config to disk.")
	}
	return err
}
