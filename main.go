package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kumakaba/acme-dns/pkg/acmedns"
	"github.com/kumakaba/acme-dns/pkg/api"
	"github.com/kumakaba/acme-dns/pkg/database"
	"github.com/kumakaba/acme-dns/pkg/nameserver"

	"go.uber.org/zap"
)

var (
	Version  = "v1.2.0"
	Revision = "preview-20251124b"
)

func main() {
	syscall.Umask(0077)
	// define commandline options
	configTestFlag := flag.Bool("t", false, "check configuration")
	configPtr := flag.String("c", "/etc/acme-dns/config.cfg", "config file location")
	versionFlag := flag.Bool("version", false, "print the version")

	flag.Parse()

	// Return Version and exit
	if *versionFlag {
		fmt.Printf("kumakaba/acme-dns (%s-%s)\n", Version, Revision)
		os.Exit(0)
	}
	// Read global config
	var err error
	var logger *zap.Logger
	config, usedConfigFile, err := acmedns.ReadConfig(*configPtr, "./config.cfg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		if *configTestFlag {
			fmt.Printf("check configuration file: %s failed\n", usedConfigFile)
		}
		os.Exit(1)
	}
	if *configTestFlag {
		fmt.Printf("check configuration file: %s succeeded\n", usedConfigFile)
		os.Exit(0)
	}
	logger, err = acmedns.SetupLogging(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not set up logging: %s\n", err)
		os.Exit(1)
	}
	// Make sure to flush the zap logger buffer before exiting
	defer logger.Sync() //nolint:all
	sugar := logger.Sugar()

	versionStr := fmt.Sprintf("%s-%s", Version, Revision)
	sugar.Infow("Using config file",
		"file", usedConfigFile)
	sugar.Infof("Starting up acme-dns %s", versionStr)

	// Initialize DB
	db, err := database.Init(&config, sugar)
	if err != nil {
		sugar.Fatalf("Failed to initialize database: %v", err)
	}

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
			sugar.Fatal(err)
		}
	case sig := <-sigChan:
		// graceful shutdown process
		sugar.Infow("Signal received, shutting down...", "signal", sig)
		if err := apiserver.Shutdown(); err != nil {
			sugar.Errorf("Failed to shutdown API server: %v", err)
		} else {
			sugar.Info("API server shutdown successfully")
		}
		for _, srv := range dnsservers {
			if err := srv.Shutdown(); err != nil {
				sugar.Errorf("Failed to shutdown a DNS server: %v", err)
			}
		}
		sugar.Info("All DNS servers shutdown successfully")

		db.Close()
		sugar.Info("acme-dns shutdown complete, bye.")
		return
	}
	for {
		err = <-errChan
		if err != nil {
			sugar.Fatal(err)
		}
	}
}
