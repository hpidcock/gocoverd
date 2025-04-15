package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

func main() {
	var err error

	var dataDir string
	var httpListenAddr string
	var tlsAutocertDomain string
	var psk string
	if os.Getenv("SNAP_NAME") == "gocoverd" {
		dataDir = os.ExpandEnv("$SNAP_COMMON/data")
		err = os.MkdirAll(dataDir, 0755)
		if err != nil {
			panic(err)
		}
		httpListenAddr, err = getSnapOption("http-listen")
		if err != nil {
			panic(err)
		}
		tlsAutocertDomain, err = getSnapOption("tls-autocert-domain")
		if err != nil {
			panic(err)
		}
		psk, err = getSnapOption("presharedkey")
		if err != nil {
			panic(err)
		}
	} else {
		flag.StringVar(&dataDir, "data-dir", "", "Directory containing coverage data")
		flag.StringVar(&httpListenAddr, "http-listen", "", "Address to listen on")
		flag.StringVar(&tlsAutocertDomain, "tls-autocert-domain", "", "Domain to use for TLS autocert")
		flag.StringVar(&psk, "presharedkey", "", "PSK for HMAC SHA256 auth")
		flag.Parse()
	}
	if dataDir == "" {
		panic("data-dir flag is required")
	}
	if httpListenAddr == "" && tlsAutocertDomain == "" {
		panic("either http-listen or tls-autocert-domain must be specified")
	}
	if httpListenAddr != "" && tlsAutocertDomain != "" {
		panic("only one of http-listen or tls-autocert-domain can be specified")
	}
	if psk == "" {
		psk = rand.Text()
		log.Printf("presharedkey=%s", psk)
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	eg, ctx := errgroup.WithContext(ctx)

	s := newServer(dataDir, []byte(psk))

	httpServer := &http.Server{
		Handler: s.Handler(),
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	var listener net.Listener
	if httpListenAddr != "" {
		listener, err = net.Listen("tcp", httpListenAddr)
		if err != nil {
			panic(err)
		}
	} else if tlsAutocertDomain != "" {
		listener = autocert.NewListener(tlsAutocertDomain)
	}

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			for _, namespace := range s.CompactableNamespaces() {
				err := s.CompactNamespace(ctx, namespace)
				if err != nil {
					log.Printf("compact namespace %s failed: %v", namespace, err)
				}
			}
		}
	})
	eg.Go(func() error {
		<-ctx.Done()
		_ = listener.Close()
		return ctx.Err()
	})
	eg.Go(func() error {
		return httpServer.Serve(listener)
	})

	err = eg.Wait()
	if err != nil {
		panic(err)
	}
}

func getSnapOption(opt string) (string, error) {
	cmd := exec.Command("snapctl", "get", opt, "-d")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	config := map[string]string{}
	err = json.Unmarshal(out, &config)
	if err != nil {
		return "", err
	}
	return config[opt], nil
}
