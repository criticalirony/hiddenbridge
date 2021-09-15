package main

import (
	"fmt"
	"hiddenbridge/options"
	"hiddenbridge/server"
	"os"
	"os/signal"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func SetupLogging(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Panic().Err(err).Msgf("Failed to parse log level: %s", level)
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(logLevel).With().Timestamp().Logger().With().Caller().Logger()
}

func ParseOptions(args []string) (opts *options.Options, err error) {
	opts = options.NewOptions("global")
	opts.CliFlag("config", "Plugin configuration YAML file")
	opts.CliFlag("v", "Log level")
	err = opts.CliParse(args)

	return
}

func main() {
	var err error
	var opts *options.Options

	if opts, err = ParseOptions(os.Args[1:]); err != nil {
		log.Panic().Err(err).Msg("command line args parse failure")
	}

	fmt.Printf("Options: %+v", opts)

	SetupLogging(opts.Get("v", "debug").String())

	// Read plugin config
	filename := opts.Get("config", "config.yml").String()

	pSvr := server.NewServer()
	pSvr.Init(filename)

	wgServerStopped := sync.WaitGroup{}
	wgServerStopped.Add(1)
	errChan := make(chan error, 1)
	go func() {
		defer wgServerStopped.Done()
		errChan <- pSvr.Start()
	}()

	<-pSvr.IsStarted()

	// Wait for stop signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	log.Info().Msg("All services stopping...")
	pSvr.Stop()
	wgServerStopped.Wait()

	// Record any errors
	err = <-errChan
	if err != nil {
		log.Panic().Err(err).Msgf("failure from %s server", pSvr.Name)
	}

	log.Info().Msg("goodbye")
}
