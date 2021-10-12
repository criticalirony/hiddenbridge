package main

import (
	"flag"
	"hiddenbridge/pkg/build"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/server"
	"hiddenbridge/pkg/utils"
	"os"
	"os/signal"

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

func ParseOptions(args []string) (opts *options.OptionValue, err error) {
	opts = &options.OptionValue{}
	flagSet := utils.NewFlagSet("", flag.ContinueOnError)

	flagSet.Func("config", "Plugin configuration YAML file", func(s string) error {
		return opts.Set("cli.config", s)
	})

	flagSet.Func("v", "Log level", func(s string) error {
		return opts.Set("cli.verbose", s)
	})

	err = flagSet.Parse(args)
	return
}

func main() {
	var err error
	var opts *options.OptionValue

	if opts, err = ParseOptions(os.Args[1:]); err != nil {
		log.Panic().Err(err).Msg("command line args parse failure")
	}

	SetupLogging(opts.GetDefault("cli.verbose", "debug").String())

	// Read plugin config
	filename := opts.GetDefault("cli.config", "config.yml").String()

	log.Info().Msg("Hidden Bridge - Servers for when you have none.")
	log.Info().Msgf("Build Version: %v Date: %v", build.Data().Version, build.Data().Date)

	pSvr := server.NewBridgeServer()
	if err := pSvr.Init(filename); err != nil {
		log.Panic().Err(err).Msgf("failed to initialize %s server", pSvr.Name)
	}

	go func() {
		if err := pSvr.Start(); err != nil {
			log.Warn().Err(err).Msg("server shutdown")
		}
	}()

	<-pSvr.IsStarted()

	// // START Explore
	// fixedURL, err := url.Parse("http://192.168.226.134:8888")
	// if err != nil {
	// 	log.Panic().Err(err).Msg("failed to parse proxy url")
	// }
	// tr := &http.Transport{
	// 	Proxy:           http.ProxyURL(fixedURL),
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	// client := &http.Client{Transport: tr}
	// resp, err := client.Get("https://192.168.226.134:8443")
	// // resp, err := client.Get("http://192.168.226.134:8080")
	// if err != nil {
	// 	log.Panic().Err(err).Msg("failed to get url through proxy")
	// }

	// log.Debug().Msgf("Resp: %+v", resp)
	// // END Explore

	// Wait for stop signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	log.Info().Msg("All services stopping...")
	pSvr.Stop()

	log.Info().Msg("goodbye")
}
