package config

import (
	"flag"
	"os"
	"time"

	"github.com/FurmanovVitaliy/logger"
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env      string         `yaml:"environment" env-default:"prod"`
	TokenTTL time.Duration  `yaml:"token_ttl" env-required:"true"`
	Logger   LoggerConfig   `yaml:"logger"`
	GRPC     GRPCConfig     `yaml:"grpc"`
	Postgres PostgresConfig `yaml:"postgres"`
}

func (c *Config) LogValue() logger.Value {
	return logger.GroupValue(
		logger.StringAttr("env", c.Env),
		logger.StringAttr("token_ttl", c.TokenTTL.String()),
		logger.Group(
			"logger",
			logger.StringAttr("level", c.Logger.Level),
			logger.BoolAttr("json", c.Logger.JSON),
			logger.BoolAttr("source", c.Logger.Source),
		),
		logger.Group(
			"grpc",
			logger.IntAttr("port", c.GRPC.Port),
			logger.DurationAttr("timeout", c.GRPC.Timeout),
		),
		logger.Group(
			"postgres",
			logger.StringAttr("host", c.Postgres.Host),
			logger.StringAttr("port", c.Postgres.Port),
			logger.StringAttr("username", c.Postgres.Username),
			logger.StringAttr("password", "REMOVED"),
			logger.StringAttr("database", c.Postgres.Database),
			logger.IntAttr("conn_retry", c.Postgres.ConnRetry),
		),
		logger.StringAttr("app_secret", "REMOVED"),
	)
}

type LoggerConfig struct {
	Level  string `yaml:"level"`
	JSON   bool   `yaml:"json" `
	Source bool   `yaml:"source" `
}

type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}

type PostgresConfig struct {
	Host      string `yaml:"host"`
	Port      string `yaml:"port"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	Database  string `yaml:"database"`
	ConnRetry int    `yaml:"conn_retry"`
}

func MustLoadByPath(configPath string) *Config {

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("failed to read config: " + err.Error())
	}

	return &cfg

}
func MustLoad() *Config {
	path := fetchConfigPath()
	if path == "" {
		panic("config path is required")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file does not exist: " + path)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic("failed to read config: " + err.Error())
	}

	return &cfg

}

// fetchConfigPath returns the path of the config file from the environment variable or comand line flag.
// Priority: command line flag > environment variable > default value
// Default value: empty string.
func fetchConfigPath() string {
	var res string

	flag.StringVar(&res, "config", "", "path to the config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}
	return res
}
