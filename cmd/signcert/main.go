package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/utils"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

func SetupLogging(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Panic().Err(err).Msgf("Failed to parse log level: %s", level)
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(logLevel).With().Timestamp().Logger().With().Caller().Logger()
}

func SaveKeys(cert []byte, privKey *rsa.PrivateKey, certFile, keyFile string) error {
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	privKeyPEM := new(bytes.Buffer)
	pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	if err := os.WriteFile(certFile, certPEM.Bytes(), 0644); err != nil {
		return xerrors.Errorf("failed to write certificate to: %s: %w", certFile, err)
	}

	log.Info().Msgf("saved cert file: %s", certFile)

	if err := os.WriteFile(keyFile, privKeyPEM.Bytes(), 0644); err != nil {
		return xerrors.Errorf("failed to write private key to: %s: %w", keyFile, err)
	}

	log.Info().Msgf("saved key file: %s", keyFile)

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return xerrors.Errorf("certificate: %s private key: %s validation failure: %w", certFile, keyFile, err)
	}

	log.Info().Msgf("certificate: %s validated against private key: %s", certFile, keyFile)

	return nil
}

func NewSignedCert(sans []string, caCert []byte, caPrivKey *rsa.PrivateKey) ([]byte, *rsa.PrivateKey, error) {
	if len(sans) == 0 {
		return nil, nil, xerrors.Errorf("failed to generate certiificate no host names provided")
	}

	for _, san := range sans {
		if san == "<nil>" {
			log.Panic().Msgf("This is from a bug in options.OptionValue which has been fixed. This should NEVER occur.")
		}

		if len(san) == 0 {
			return nil, nil, xerrors.Errorf("invalid/empty hostname supplied")
		}
	}

	// from https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Default Company Ltd"},
			Country:       []string{"XX"},
			Province:      []string{""},
			Locality:      []string{"Default City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			// CommonName:    chi.ServerName,
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     append([]string{}, sans...),
		NotBefore:    time.Now().AddDate(0, 0, -7),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, // Very important Centos 7 needs "x509.KeyUsageKeyEncipherment"
	}

	sitePrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, xerrors.Errorf("generating site rsa key failure: %w", err)
	}

	log.Info().Msgf("private key for host: %s generated", sans[0])

	parentCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, nil, xerrors.Errorf("parsing parent certificate failure: %w", err)
	}

	siteCert, err := x509.CreateCertificate(rand.Reader, cert, parentCert, &sitePrivKey.PublicKey, caPrivKey)
	if err != nil {
		err = xerrors.Errorf("create site certificate failure: %w", err)
		return nil, nil, err
	}

	log.Info().Msgf("certificate for host: %s generated", sans[0])

	return siteCert, sitePrivKey, nil
}

func LoadKeys(certFile, keyFile string) ([]byte, *rsa.PrivateKey, error) {
	certPem, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, xerrors.Errorf("failure to read file: %s: %w", certFile, err)
	}
	log.Info().Msgf("loaded cert file: %s", certFile)

	keyPem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, xerrors.Errorf("failure to read file: %s: %w", keyFile, err)
	}

	log.Info().Msgf("loaded key file: %s", keyFile)

	certPemBlock, _ := pem.Decode(certPem)
	keyPemBlock, _ := pem.Decode(keyPem)

	privKey, err := x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
	if err != nil {
		return nil, nil, xerrors.Errorf("failure to parse RSA private key")
	}

	log.Info().Msg("certificate and key successfully parsed")

	return certPemBlock.Bytes, privKey, nil
}

func main() {
	var err error
	opts := &options.OptionValue{}

	flagSet := utils.NewFlagSet("", flag.ExitOnError)

	flagSet.Func("v", "Verbose level", func(s string) error {
		return opts.Set("cli.verbose", s)
	})

	flagSet.Func("out", "Out cert file", func(s string) error {
		return opts.Set("cli.out.cert", s)
	})

	flagSet.Func("out-key", "Out cert key", func(s string) error {
		return opts.Set("cli.out.key", s) // Certificate out file
	})

	flagSet.Func("in", "CA cert file", func(s string) error {
		return opts.Set("cli.in.cert", s) // CA in certificate file
	})

	flagSet.Func("in-key", "CA key file", func(s string) error {
		return opts.Set("cli.in.key", s) // CA in key file
	})

	flagSet.Func("n", "Subect Alt Name (host). Can be used multiple times.", func(s string) error {
		valList := opts.GetDefault("cli.host", nil).List()
		valList = append(valList, options.OptionValue{Value: s}) // Can be a list, provide multiple -h
		return opts.Set("cli.host", valList)
	})

	if err = flagSet.Parse(os.Args[1:]); err != nil {
		log.Panic().Err(err).Msg("failed to parse cli options")
	}

	SetupLogging(opts.GetDefault("cli.verbose", "debug").String())

	log.Info().Msg("signcert: creating signed certificates the easy way")

	hostOpts := opts.GetDefault("cli.host", nil).List()
	if len(hostOpts) == 0 {
		log.Panic().Msgf("At least one \"-n\" <alt name (host)> must be provided")
	}

	hostList := make([]string, len(hostOpts))
	for i, hostOpt := range hostOpts {
		hostList[i] = hostOpt.String()
	}

	caCert, caPrivKey, err := LoadKeys(opts.GetDefault("cli.in.cert", "").String(), opts.GetDefault("cli.in.key", "").String())
	if err != nil {
		log.Panic().Err(err).Msg("failed to load CA cert and key")
	}

	siteCert, sitePrivKey, err := NewSignedCert(hostList, caCert, caPrivKey)
	if err != nil {
		log.Panic().Err(err).Msgf("failed to generate new signed cert for hosts: %v", hostList)
	}

	if err := SaveKeys(siteCert, sitePrivKey, opts.GetDefault("cli.out.cert", "").String(), opts.GetDefault("cli.out.key", "").String()); err != nil {
		log.Panic().Err(err).Msgf("failed to save signed cert and key files")
	}
}
