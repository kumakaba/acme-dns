package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/kumakaba/acme-dns/pkg/acmedns"
	"github.com/kumakaba/acme-dns/pkg/api"
	"github.com/kumakaba/acme-dns/pkg/database"
	"github.com/kumakaba/acme-dns/pkg/nameserver"

	"go.uber.org/zap"
)

var (
	Version  = "v1.2.0"
	Revision = "preview-20251123b"
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

	sugar.Infow("Using config file",
		"file", usedConfigFile)
	sugar.Info("Starting up")
	db, err := database.Init(&config, sugar)
	// Error channel for servers
	errChan := make(chan error, 1)
	api := api.Init(&config, db, sugar, errChan)
	versionStr := fmt.Sprintf("%s-%s", Version, Revision)
	dnsservers := nameserver.InitAndStart(&config, db, sugar, errChan, versionStr)
	go api.Start(dnsservers)
	if err != nil {
		sugar.Error(err)
	}
	for {
		err = <-errChan
		if err != nil {
			sugar.Fatal(err)
		}
	}
}
