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
	"maps"
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

	cleanupMut sync.Mutex

	mut             sync.Mutex
	writingProfiles map[uuid.UUID]chan struct{}
	needsCompact    map[string]int
}

func newServer(dataDir string, psk []byte) *server {
	closedChan := make(chan struct{})
	close(closedChan)
	return &server{
		psk:             psk,
		dataDir:         dataDir,
		dataDirFS:       os.DirFS(dataDir),
		writingProfiles: make(map[uuid.UUID]chan struct{}),
		needsCompact:    make(map[string]int),
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
			s.needsCompact[namespaceToCompact]++
		}
	}
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

	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dir)
		}
	}()

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
	complete = true
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

	s.cleanupMut.Lock()
	defer s.cleanupMut.Unlock()
	result, err := s.compactNamespace(context.Background(), namespace, dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if result == "" {
		log.Printf("no coverage data found")
		http.Error(w, "no coverage data found", http.StatusNotFound)
		return
	}
	resultDir := path.Join(dir, result)

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", "attachment; filename=mergedcovdata.tar.gz")
	w.WriteHeader(http.StatusOK)
	gzw := gzip.NewWriter(w)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()
	err = tw.AddFS(os.DirFS(resultDir))
	if err != nil {
		log.Printf("failed to add directory to tar: %v", err)
		return
	}
}

const minCompactCount = 32

func (s *server) CompactableNamespaces() []string {
	s.mut.Lock()
	defer s.mut.Unlock()
	var namespaces []string
	for namespace, count := range s.needsCompact {
		if count > minCompactCount {
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

	s.cleanupMut.Lock()
	defer s.cleanupMut.Unlock()
	_, err = s.compactNamespace(ctx, namespace, dir)
	if err != nil {
		return err
	}
	return nil
}

func (s *server) compactNamespace(ctx context.Context, namespace string, dir string) (string, error) {
	s.mut.Lock()
	delete(s.needsCompact, namespace)
	writingProfiles := maps.Clone(s.writingProfiles)
	entries, err := os.ReadDir(dir)
	s.mut.Unlock()
	if err != nil {
		return "", fmt.Errorf("failed to read directory: %w", err)
	}

	profileDirs := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		id, err := uuid.Parse(name)
		if err != nil {
			continue
		}
		if ch, ok := writingProfiles[id]; ok {
			select {
			case <-ch:
			case <-ctx.Done():
				return "", ctx.Err()
			}
			_, err := os.Stat(path.Join(dir, name))
			if errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return "", err
			}
		}
		profileDirs = append(profileDirs, name)
	}
	if len(profileDirs) == 0 {
		return "", nil
	}
	if len(profileDirs) == 1 {
		return profileDirs[0], nil
	}

	collected, err := s.collect(ctx, dir, profileDirs)
	if err != nil {
		return "", fmt.Errorf("failed to compact/collect namespace %q: %w", namespace, err)
	}

	result, err := s.compact(ctx, dir, collected)
	if err != nil {
		return "", fmt.Errorf("failed to compact namespace %q: %w", namespace, err)
	}

	log.Printf("compacted %d profiles in namespace %q into %s", len(profileDirs), namespace, result)
	return result, nil
}

func (s *server) collect(ctx context.Context, dir string, profileDirs []string) (string, error) {
	counters := map[string]string{}
	meta := map[string]string{}

	for _, profile := range profileDirs {
		profileDir := path.Join(dir, profile)
		err := s.collectOne(ctx, profileDir, counters, meta)
		if err != nil {
			return "", fmt.Errorf("collecting profile %q", profile)
		}
	}

	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	unlock := s.writing("", id)
	defer unlock()

	outDir := path.Join(dir, id.String())
	err = os.Mkdir(outDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	for metaHash, metaSource := range meta {
		inMeta, err := os.Open(metaSource)
		if err != nil {
			_ = os.RemoveAll(outDir)
			return "", err
		}

		metaPath := path.Join(outDir, "covmeta."+metaHash)
		outMeta, err := os.Create(metaPath)
		if err != nil {
			_ = inMeta.Close()
			_ = os.RemoveAll(outDir)
			return "", err
		}

		_, err = io.Copy(outMeta, inMeta)
		_ = outMeta.Close()
		_ = inMeta.Close()
		if err != nil {
			_ = os.RemoveAll(outDir)
			return "", err
		}
	}

	for counterSource, counterName := range counters {
		inCounter, err := os.Open(counterSource)
		if err != nil {
			_ = os.RemoveAll(outDir)
			return "", err
		}

		counterPath := path.Join(outDir, counterName)
		outCounter, err := os.Create(counterPath)
		if err != nil {
			_ = inCounter.Close()
			_ = os.RemoveAll(outDir)
			return "", err
		}

		_, err = io.Copy(outCounter, inCounter)
		_ = outCounter.Close()
		_ = inCounter.Close()
		if err != nil {
			_ = os.RemoveAll(outDir)
			return "", err
		}
	}

	for _, subDir := range profileDirs {
		err := os.RemoveAll(path.Join(dir, subDir))
		if err != nil {
			slog.Error("failed to remove directory", "dir", subDir, "err", err)
			continue
		}
	}

	return id.String(), nil
}

func (s *server) collectOne(ctx context.Context, dir string, counters map[string]string, meta map[string]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	mapper := map[string]string{}
	for _, f := range entries {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if !strings.HasPrefix(name, "covmeta.") {
			continue
		}
		metaName := strings.TrimPrefix(name, "covmeta.")
		metaPath := path.Join(dir, name)
		metaFile, err := os.Open(metaPath)
		if err != nil {
			return err
		}
		hasher := sha256.New()
		_, err = io.Copy(hasher, metaFile)
		metaFile.Close()
		if err != nil {
			return err
		}
		metaHash := hex.EncodeToString(hasher.Sum(nil))
		mapper[metaName] = metaHash
		meta[metaHash] = metaPath
	}

	for _, f := range entries {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if !strings.HasPrefix(name, "covcounters.") {
			continue
		}
		nameParts := strings.Split(name, ".")
		if len(nameParts) != 4 {
			return fmt.Errorf("covcounter file with wrong name %q", name)
		}
		metaName := nameParts[1]
		metaHash := mapper[metaName]
		if metaHash == "" {
			return fmt.Errorf("covcounter file missing matching meta %q", name)
		}
		counterPath := path.Join(dir, name)
		nameParts[1] = metaHash
		newName := strings.Join(nameParts, ".")
		counters[counterPath] = newName
	}

	return nil
}

const maxProfilesPerJob = 2048

func (s *server) compact(ctx context.Context, dir string, profileDir string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	unlock := s.writing("", id)
	defer unlock()

	outDir := path.Join(dir, id.String())
	err = os.Mkdir(outDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}
	if !path.IsAbs(outDir) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		outDir = path.Join(wd, outDir)
	}

	cmd := exec.CommandContext(ctx, "go", "tool", "covdata", "merge", "-i="+profileDir, "-o="+outDir, "-pcombine")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		os.RemoveAll(outDir)
		return "", fmt.Errorf("failed to merge coverage data: %w", err)
	}

	err = os.RemoveAll(path.Join(dir, profileDir))
	if err != nil {
		slog.Error("failed to remove directory", "dir", profileDir, "err", err)
	}

	return id.String(), nil
}
