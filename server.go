package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type server struct {
	psk       []byte
	dataDir   string
	dataDirFS fs.FS

	mut             sync.Mutex
	writingProfiles map[uuid.UUID]chan struct{}
	needsCompact    map[string]bool

	closedChan <-chan struct{}
}

func newServer(dataDir string, psk []byte) *server {
	closedChan := make(chan struct{})
	close(closedChan)
	return &server{
		psk:             psk,
		dataDir:         dataDir,
		dataDirFS:       os.DirFS(dataDir),
		writingProfiles: make(map[uuid.UUID]chan struct{}),
		needsCompact:    make(map[string]bool),
		closedChan:      closedChan,
	}
}

func (s *server) writing(namespaceToCompact string, profile uuid.UUID) func() {
	s.mut.Lock()
	defer s.mut.Unlock()
	s.writingProfiles[profile] = make(chan struct{})
	return func() {
		s.mut.Lock()
		defer s.mut.Unlock()
		close(s.writingProfiles[profile])
		delete(s.writingProfiles, profile)
		if namespaceToCompact != "" {
			s.needsCompact[namespaceToCompact] = true
		}
	}
}

func (s *server) reading(namespace string, profile uuid.UUID) <-chan struct{} {
	s.mut.Lock()
	defer s.mut.Unlock()
	var ch <-chan struct{} = s.writingProfiles[profile]
	if ch == nil {
		ch = s.closedChan
	}
	return ch
}

func (s *server) Handler() http.Handler {
	r := mux.NewRouter()
	r.Path("/{namespace}/covdata").Methods(http.MethodPut).HandlerFunc(s.HandleUpload)
	r.Path("/{namespace}/covdata").Methods(http.MethodGet).HandlerFunc(s.HandleDownload)
	r.Path("/{namespace}").Methods(http.MethodPut).HandlerFunc(s.HandleCreate)
	return r
}

const maxInfoLength = 256

func (s *server) HandleCreate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	namespace := vars["namespace"]
	if !isSHA256(namespace) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.ContentLength < 1 || r.ContentLength > maxInfoLength {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	buffer := &bytes.Buffer{}
	m := hmac.New(sha256.New, s.psk)
	written, err := io.Copy(m, io.TeeReader(io.LimitReader(r.Body, r.ContentLength), buffer))
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if written != r.ContentLength {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	namespaceBytes, err := hex.DecodeString(namespace)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	mac := m.Sum(nil)
	if !bytes.Equal(mac, namespaceBytes) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	dir := path.Join(s.dataDir, namespace)
	err = os.Mkdir(dir, 0755)
	if errors.Is(err, os.ErrExist) {
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	info := path.Join(dir, "info")
	err = os.WriteFile(info, buffer.Bytes(), 0644)
	if errors.Is(err, os.ErrExist) {
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Error(w, "OK", http.StatusOK)
}

func (s *server) HandleUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	namespace := vars["namespace"]
	namespaceDir, err := checkNamespace(s.dataDirFS, namespace)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	id, err := uuid.NewV7()
	if err != nil {
		log.Printf("failed to generate UUID: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	unlock := s.writing(namespace, id)
	defer unlock()

	dir := path.Join(s.dataDir, namespaceDir, id.String())
	err = os.Mkdir(dir, 0755)
	if err != nil {
		log.Printf("failed to create directory %q: %v", dir, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	gzipReader, err := gzip.NewReader(r.Body)
	if err != nil {
		log.Printf("failed to create gzip reader: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			log.Printf("failed to read tar header: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if header.Typeflag != tar.TypeReg {
			log.Printf("invalid file type: %s", header.Name)
			http.Error(w, fmt.Sprintf("invalid file type: %s", header.Name), http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(header.Name, ".") {
			log.Printf("invalid file name: %s", header.Name)
			http.Error(w, fmt.Sprintf("invalid file name: %s", header.Name), http.StatusBadRequest)
			return
		}
		if strings.Contains(header.Name, "/") {
			log.Printf("invalid file name: %s", header.Name)
			http.Error(w, fmt.Sprintf("invalid file name: %s", header.Name), http.StatusBadRequest)
			return
		}
		f, err := os.Create(path.Join(dir, header.Name))
		if err != nil {
			log.Printf("failed to create file %q: %v", path.Join(dir, header.Name), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := io.Copy(f, tarReader); errors.Is(err, io.EOF) {
			f.Close()
			continue
		} else if err != nil {
			f.Close()
			log.Printf("failed to copy file %q: %v", path.Join(dir, header.Name), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	http.Error(w, "OK", http.StatusOK)
}

func (s *server) HandleDownload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	namespace := vars["namespace"]
	namespaceDir, err := checkNamespace(s.dataDirFS, namespace)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	dir := path.Join(s.dataDir, namespaceDir)

	s.mut.Lock()
	entries, err := os.ReadDir(dir)
	s.mut.Unlock()
	if err != nil {
		log.Printf("failed to read directory %q: %v", dir, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	subDirectories := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		id, err := uuid.Parse(name)
		if err != nil {
			log.Printf("failed to parse UUID from directory name %q: %v", name, err)
			continue
		}
		select {
		case <-s.reading(namespace, id):
		case <-r.Context().Done():
			http.Error(w, "request cancelled", http.StatusRequestTimeout)
			return
		}
		subDirectories = append(subDirectories, name)
	}
	if len(subDirectories) == 0 {
		log.Printf("no coverage data found")
		http.Error(w, "no coverage data found", http.StatusNotFound)
		return
	}

	tempDir, err := os.MkdirTemp("", "mergedcovdata*")
	if err != nil {
		log.Printf("failed to create temporary directory: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tempDir)

	cmd := exec.CommandContext(r.Context(), "go", "tool", "covdata", "merge", "-i="+strings.Join(subDirectories, ","), "-o="+tempDir, "-pcombine")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Printf("failed to merge coverage data: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", "attachment; filename=mergedcovdata.tar.gz")
	w.WriteHeader(http.StatusOK)
	gzw := gzip.NewWriter(w)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()
	err = tw.AddFS(os.DirFS(tempDir))
	if err != nil {
		log.Printf("failed to add directory to tar: %v", err)
		return
	}
}

func (s *server) CompactableNamespaces() []string {
	s.mut.Lock()
	defer s.mut.Unlock()
	var namespaces []string
	for namespace, ok := range s.needsCompact {
		if ok {
			namespaces = append(namespaces, namespace)
		}
	}
	return namespaces
}

func (s *server) CompactNamespace(ctx context.Context, namespace string) error {
	namespaceDir, err := checkNamespace(s.dataDirFS, namespace)
	if err != nil {
		return nil
	}
	dir := path.Join(s.dataDir, namespaceDir)

	s.mut.Lock()
	compactNeeded := s.needsCompact[namespace]
	delete(s.needsCompact, namespace)
	if !compactNeeded {
		s.mut.Unlock()
		return nil
	}
	entries, err := os.ReadDir(dir)
	s.mut.Unlock()
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	subDirectories := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		id, err := uuid.Parse(name)
		if err != nil {
			continue
		}
		select {
		case <-s.reading(namespace, id):
		case <-ctx.Done():
			return ctx.Err()
		}
		unlock := s.writing("", id)
		defer unlock()
		subDirectories = append(subDirectories, name)
	}
	if len(subDirectories) == 0 {
		return nil
	}

	id, err := uuid.NewV7()
	if err != nil {
		return err
	}

	unlock := s.writing("", id)
	defer unlock()

	outDir := path.Join(s.dataDir, namespaceDir, id.String())
	err = os.Mkdir(outDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	if !path.IsAbs(outDir) {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		outDir = path.Join(wd, outDir)
	}

	cmd := exec.CommandContext(ctx, "go", "tool", "covdata", "merge", "-i="+strings.Join(subDirectories, ","), "-o="+outDir, "-pcombine")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		os.RemoveAll(outDir)
		return fmt.Errorf("failed to merge coverage data: %w", err)
	}

	s.mut.Lock()
	defer s.mut.Unlock()
	for _, subDir := range subDirectories {
		err := os.RemoveAll(path.Join(dir, subDir))
		if err != nil {
			slog.Error("failed to remove directory", "dir", subDir, "err", err)
			continue
		}
	}

	log.Printf("compacted %d profiles in namespace %q", len(subDirectories), namespace)
	return nil
}
