package main

import (
	"context"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"webauthndemo/pkg/api"
	"webauthndemo/pkg/config"
	"webauthndemo/pkg/db"
)

func main() {
	cfg := &config.AppSettings{
		Debug:        true,
		ListenAddr:   ":8080",
		StaticPages:  "./views",
		DBServiceURL: "file:///tmp/demo.db",
	}
	if err := config.ReadConfig(cfg); err != nil {
		logrus.WithError(err).Fatal("config failure")
	}

	var dbsvc *db.DBService
	if cfg.DBServiceURL != "" {
		var err error
		dbsvc, err = db.NewDBService(cfg.DBServiceURL)
		if err != nil {
			logrus.WithField("urn", cfg.DBServiceURL).WithError(err).Fatal("config failure to connect to database")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	logrus.WithField("addr", cfg.ListenAddr).Info("starting webauthndemo")
	svrDone := make(chan error, 1)
	svr, err := api.NewServer(cfg, dbsvc)
	if err != nil {
		logrus.WithError(err).Fatal("unable to init proxy")
	}
	svr.StartServer(svrDone)

	select {
	case signo := <-sigc:
		logrus.WithField("signal", signo).Info("got signal")
	case <-ctx.Done():
		logrus.Info("got context done")
	case err := <-svrDone:
		if err != http.ErrServerClosed {
			logrus.WithError(err).Error("server exited")
		}
	}
	_ = svr.Stop(ctx)

	logrus.Info("webauthndemo exiting")
}
