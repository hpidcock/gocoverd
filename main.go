package main

import (
	"context"
	"flag"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

func main() {
	var err error

	var dataDir string
	var httpListenAddr string
	var tlsAutocertDomain string
	flag.StringVar(&dataDir, "data-dir", "", "Directory containing coverage data")
	flag.StringVar(&httpListenAddr, "http-listen", "", "Address to listen on")
	flag.StringVar(&tlsAutocertDomain, "tls-autocert-domain", "", "Domain to use for TLS autocert")
	flag.Parse()
	if dataDir == "" {
		panic("data-dir flag is required")
	}

	if httpListenAddr == "" && tlsAutocertDomain == "" {
		panic("either http-listen or tls-autocert-domain must be specified")
	}
	if httpListenAddr != "" && tlsAutocertDomain != "" {
		panic("only one of http-listen or tls-autocert-domain can be specified")
	}

	eg, ctx := errgroup.WithContext(context.Background())

	s := newServer(dataDir)

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
			case <-time.After(30 * time.Second):
			}
			for _, namespace := range s.CompactableNamespaces() {
				err := s.CompactNamespace(ctx, namespace)
				if err != nil {
					return err
				}
			}
		}
	})
	eg.Go(func() error {
		return httpServer.Serve(listener)
	})

	err = eg.Wait()
	if err != nil {
		panic(err)
	}
}
