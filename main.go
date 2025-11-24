package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kumakaba/acme-dns/pkg/acmedns"
	"github.com/kumakaba/acme-dns/pkg/api"
	"github.com/kumakaba/acme-dns/pkg/database"
	"github.com/kumakaba/acme-dns/pkg/nameserver"

	"go.uber.org/zap"
)

var (
	Version  = "v1.3.0"
	Revision = "preview20251125a"
)

func main() {
	syscall.Umask(0077)
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// define commandline options
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	configTestFlag := fs.Bool("t", false, "check configuration")
	configPtr := fs.String("c", "/etc/acme-dns/config.cfg", "config file location")
	versionFlag := fs.Bool("version", false, "print the version")

	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}

	// Return Version and exit
	if *versionFlag {
		fmt.Fprintf(stdout, "kumakaba/acme-dns (%s-%s)\n", Version, Revision)
		return 0
	}
	// Read global config
	var err error
	var logger *zap.Logger
	config, usedConfigFile, err := acmedns.ReadConfig(*configPtr, "./config.cfg")
	if err != nil {
		fmt.Fprintf(stderr, "Error: %s\n", err)
		if *configTestFlag {
			fmt.Fprintf(stdout, "check configuration file: %s failed\n", usedConfigFile)
		}
		return 1
	}
	if *configTestFlag {
		fmt.Fprintf(stdout, "check configuration file: %s succeeded\n", usedConfigFile)
		return 0
	}
	logger, err = acmedns.SetupLogging(config)
	if err != nil {
		fmt.Fprintf(stderr, "Could not set up logging: %s\n", err)
		return 1
	}
	// Make sure to flush the zap logger buffer before exiting
	defer func() { _ = logger.Sync() }()
	sugar := logger.Sugar()

	versionStr := fmt.Sprintf("%s-%s", Version, Revision)
	sugar.Infow("Using config file",
		"file", usedConfigFile)
	sugar.Infof("Starting up acme-dns %s", versionStr)

	// Initialize DB
	db, err := database.Init(&config, sugar)
	if err != nil {
		sugar.Errorf("Failed to initialize database: %v", err)
		return 1
	}
	defer db.Close()

	// Error channel for servers
	errChan := make(chan error, 1)

	// Signal channel for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Initialize API and DNS servers
	apiserver := api.Init(&config, db, sugar, errChan)
	dnsservers := nameserver.InitAndStart(&config, db, sugar, errChan, versionStr)
	go apiserver.Start(dnsservers)

	select {
	case err := <-errChan:
		if err != nil {
			sugar.Error(err)
			return 1
		}
	case sig := <-sigChan:
		// graceful shutdown process
		sugar.Infow("Signal received, shutting down...", "signal", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := apiserver.Shutdown(ctx); err != nil {
			sugar.Errorf("Failed to shutdown API server: %v", err)
		} else {
			sugar.Info("API server shutdown successfully")
		}
		for _, srv := range dnsservers {
			if err := srv.Shutdown(ctx); err != nil {
				sugar.Errorf("Failed to shutdown a DNS server: %v", err)
			}
		}
		sugar.Info("All DNS servers shutdown successfully")

		sugar.Info("acme-dns shutdown complete, bye.")
		return 0
	}
	for {
		err = <-errChan
		if err != nil {
			sugar.Error(err)
			return 1
		}
	}
}
