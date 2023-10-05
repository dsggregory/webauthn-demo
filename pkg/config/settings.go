package config

import (
	"fmt"
	"github.com/dsggregory/config"
	"github.com/sirupsen/logrus"
)

type AppSettings struct {
	Debug bool `usage:"Turn on debug mode"`
	// ListenAddr address to listen for client connections to this server
	ListenAddr   string `usage:"address to listen for client connections to this server"`
	WebsiteURL   string `usage:"specifies the base URL for external access to the server needed for redirection et.al."`
	StaticPages  string `usage:"path to static web pages relative to where the server is started"`
	DBServiceURL string `"flag:"db-service-url" env:"DB_SERVICE_URL" usage:"the DSN of the database for contacts, et.al."`
}

// ReadConfig using default values from the arg, read config settings from cmdline or environment. Modifies the pointer to defaults.
func ReadConfig(defaults *AppSettings) error {
	err := config.ReadConfig(defaults)
	if err != nil {
		return fmt.Errorf("configuration loading failed")
	}
	if defaults.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	return nil
}
