// Package rag provides Retrieval-Augmented Generation (RAG) capabilities for
// kube-diagnose. This file implements a document loader that ingests Markdown
// and plain-text runbooks, postmortems, and guides from the local filesystem
// or from Kubernetes ConfigMaps.
package rag

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// -----------------------------------------------------------------------------
// Domain types
// -----------------------------------------------------------------------------

// DocumentType classifies a document by its content category. The value is
// inferred from the parent subdirectory name when loading from a filesystem.
type DocumentType string

const (
	// DocumentTypeRunbook represents a runbook — an operational guide for
	// responding to a known failure mode.
	DocumentTypeRunbook DocumentType = "runbook"

	// DocumentTypePostmortem represents a postmortem — a retrospective analysis
	// of a past incident with root cause and remediation.
	DocumentTypePostmortem DocumentType = "postmortem"

	// DocumentTypeGuide represents a general-purpose guide or how-to article.
	DocumentTypeGuide DocumentType = "guide"

	// DocumentTypeUnknown is used when the type cannot be inferred.
	DocumentTypeUnknown DocumentType = "unknown"
)

// Document is the fundamental unit of content managed by the RAG system.
// Each document is stored with its full content; chunking produces derivative
// Documents that inherit the parent's metadata.
type Document struct {
	// ID is a unique identifier for this document or chunk.
	ID string

	// Title is a human-readable label, typically derived from the filename.
	Title string

	// Content is the raw text content of the document or chunk.
	Content string

	// Type classifies the document (runbook, postmortem, guide, etc.).
	Type DocumentType

	// Source is the origin path or ConfigMap key from which this document
	// was loaded.
	Source string

	// Tags are free-form labels attached to the document, e.g. derived from
	// directory structure or front-matter.
	Tags []string
}

// -----------------------------------------------------------------------------
// DocumentLoader
// -----------------------------------------------------------------------------

// DocumentLoader reads documents from filesystem directories or ConfigMaps and
// optionally splits them into overlapping chunks suitable for embedding.
type DocumentLoader struct {
	logger *zap.Logger
}

// NewDocumentLoader constructs a DocumentLoader.
func NewDocumentLoader(logger *zap.Logger) *DocumentLoader {
	return &DocumentLoader{
		logger: logger.With(zap.String("component", "document_loader")),
	}
}

// supportedExtension reports whether the given file extension should be loaded.
func supportedExtension(ext string) bool {
	switch strings.ToLower(ext) {
	case ".md", ".txt":
		return true
	default:
		return false
	}
}

// inferDocumentType determines the document type from a directory path.
// It inspects path components for well-known subdirectory names.
func inferDocumentType(path string) DocumentType {
	// Normalise to forward-slash separated components for matching.
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		switch strings.ToLower(part) {
		case "runbooks", "runbook":
			return DocumentTypeRunbook
		case "postmortems", "postmortem":
			return DocumentTypePostmortem
		case "guides", "guide":
			return DocumentTypeGuide
		}
	}
	return DocumentTypeUnknown
}

// titleFromFilename derives a human-readable title from a filename by stripping
// the extension and replacing hyphens and underscores with spaces.
func titleFromFilename(filename string) string {
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	// Replace separators with spaces for readability.
	base = strings.ReplaceAll(base, "-", " ")
	base = strings.ReplaceAll(base, "_", " ")
	return strings.TrimSpace(base)
}

// documentID generates a stable, human-readable identifier for a document
// loaded from an absolute filesystem path. It uses the relative portion of the
// path from dirPath onward, with path separators replaced by underscores.
func documentID(dirPath, absPath string) string {
	rel, err := filepath.Rel(dirPath, absPath)
	if err != nil {
		rel = absPath
	}
	rel = filepath.ToSlash(rel)
	// Remove extension.
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	// Replace slashes and spaces with underscores.
	rel = strings.ReplaceAll(rel, "/", "_")
	rel = strings.ReplaceAll(rel, " ", "_")
	return strings.ToLower(rel)
}

// LoadFromDirectory walks dirPath recursively and loads all .md and .txt files.
// For each file the document type is inferred from its parent subdirectory name.
// Returns an error only if the root directory cannot be accessed; individual
// file read errors are logged and skipped.
func (l *DocumentLoader) LoadFromDirectory(dirPath string) ([]Document, error) {
	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("stat directory %q: %w", dirPath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q is not a directory", dirPath)
	}

	var docs []Document

	walkErr := filepath.Walk(dirPath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			l.logger.Warn("error accessing path during walk, skipping",
				zap.String("path", path),
				zap.Error(err),
			)
			return nil // continue walking
		}
		if fi.IsDir() {
			return nil // descend into subdirectories
		}

		ext := filepath.Ext(fi.Name())
		if !supportedExtension(ext) {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			l.logger.Warn("could not read file, skipping",
				zap.String("path", path),
				zap.Error(readErr),
			)
			return nil
		}

		docType := inferDocumentType(path)
		tags := tagsFromPath(dirPath, path)

		doc := Document{
			ID:      documentID(dirPath, path),
			Title:   titleFromFilename(fi.Name()),
			Content: string(content),
			Type:    docType,
			Source:  path,
			Tags:    tags,
		}

		docs = append(docs, doc)
		l.logger.Debug("loaded document",
			zap.String("id", doc.ID),
			zap.String("title", doc.Title),
			zap.String("type", string(doc.Type)),
			zap.Int("contentBytes", len(content)),
		)
		return nil
	})

	if walkErr != nil {
		return nil, fmt.Errorf("walk directory %q: %w", dirPath, walkErr)
	}

	l.logger.Info("loaded documents from directory",
		zap.String("path", dirPath),
		zap.Int("count", len(docs)),
	)
	return docs, nil
}

// tagsFromPath derives a tag list from the relative path components between
// dirPath and the document path. Each intermediate directory becomes a tag.
func tagsFromPath(dirPath, absPath string) []string {
	rel, err := filepath.Rel(dirPath, absPath)
	if err != nil {
		return nil
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	// Exclude the filename itself (last element).
	if len(parts) <= 1 {
		return nil
	}
	tags := make([]string, 0, len(parts)-1)
	for _, p := range parts[:len(parts)-1] {
		if p != "" && p != "." {
			tags = append(tags, strings.ToLower(p))
		}
	}
	return tags
}

// -----------------------------------------------------------------------------
// Chunking
// -----------------------------------------------------------------------------

// defaultChunkSize is the default number of words per chunk.
const defaultChunkSize = 512

// defaultOverlap is the default number of words shared between consecutive chunks.
const defaultOverlap = 50

// ChunkDocument splits a large document into overlapping word-based chunks.
// chunkSize is the number of words per chunk; overlap is the number of words
// repeated at the start of each subsequent chunk. Both values must be positive;
// if not, defaults are used.
//
// Each chunk inherits the parent document's metadata and receives a unique ID
// suffixed with its index (e.g. "my_doc_chunk_0", "my_doc_chunk_1", …).
//
// If the document content fits within a single chunk it is returned as-is.
func (l *DocumentLoader) ChunkDocument(doc Document, chunkSize, overlap int) []Document {
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if overlap < 0 {
		overlap = defaultOverlap
	}
	if overlap >= chunkSize {
		overlap = chunkSize / 2
		l.logger.Warn("overlap must be less than chunkSize, clamped to half of chunkSize",
			zap.Int("chunkSize", chunkSize),
			zap.Int("overlap", overlap),
		)
	}

	words := tokenizeWords(doc.Content)

	// No chunking needed if the document fits in one chunk.
	if len(words) <= chunkSize {
		return []Document{doc}
	}

	step := chunkSize - overlap
	var chunks []Document
	chunkIndex := 0

	for start := 0; start < len(words); start += step {
		end := start + chunkSize
		if end > len(words) {
			end = len(words)
		}

		chunkContent := strings.Join(words[start:end], " ")

		chunk := Document{
			ID:      fmt.Sprintf("%s_chunk_%d", doc.ID, chunkIndex),
			Title:   fmt.Sprintf("%s (chunk %d)", doc.Title, chunkIndex),
			Content: chunkContent,
			Type:    doc.Type,
			Source:  doc.Source,
			Tags:    doc.Tags,
		}

		chunks = append(chunks, chunk)
		chunkIndex++

		// Avoid infinite loop if step is 0 (should not happen given the
		// overlap < chunkSize guarantee, but guard defensively).
		if step <= 0 {
			break
		}

		// If we've consumed all words, stop.
		if end >= len(words) {
			break
		}
	}

	l.logger.Debug("chunked document",
		zap.String("id", doc.ID),
		zap.Int("totalWords", len(words)),
		zap.Int("chunkSize", chunkSize),
		zap.Int("overlap", overlap),
		zap.Int("chunks", len(chunks)),
	)
	return chunks
}

// tokenizeWords splits text into individual words using a bufio.Scanner with
// the ScanWords split function. This correctly handles multiple whitespace
// characters and newlines.
func tokenizeWords(text string) []string {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Split(bufio.ScanWords)

	var words []string
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}
	return words
}

// -----------------------------------------------------------------------------
// ConfigMap loader
// -----------------------------------------------------------------------------

// LoadFromConfigMap creates a Document for each key-value pair in data.
// The key is treated as the document name (and used to derive the title and ID),
// while the value is the full document content.
//
// The document type is inferred from the key using the same directory-name
// heuristic as LoadFromDirectory (e.g. a key of "runbooks/oom-killer.md" yields
// type DocumentTypeRunbook).
//
// This method never returns an error for individual entries; it logs warnings
// and continues. It returns a non-nil error only if data is nil.
func (l *DocumentLoader) LoadFromConfigMap(data map[string]string) ([]Document, error) {
	if data == nil {
		return nil, fmt.Errorf("ConfigMap data map must not be nil")
	}

	docs := make([]Document, 0, len(data))

	for key, content := range data {
		if strings.TrimSpace(content) == "" {
			l.logger.Warn("ConfigMap entry has empty content, skipping",
				zap.String("key", key),
			)
			continue
		}

		docType := inferDocumentType(key)

		// Derive a stable ID from the key by sanitising it.
		id := strings.ToLower(key)
		id = strings.ReplaceAll(id, "/", "_")
		id = strings.ReplaceAll(id, ".", "_")
		id = strings.ReplaceAll(id, " ", "_")
		id = strings.TrimPrefix(id, "_")

		// Derive a human-readable title from the final path component.
		parts := strings.Split(filepath.ToSlash(key), "/")
		rawTitle := parts[len(parts)-1]
		title := titleFromFilename(rawTitle)
		if title == "" {
			title = key
		}

		// Derive tags from intermediate path components.
		var tags []string
		if len(parts) > 1 {
			for _, p := range parts[:len(parts)-1] {
				if p != "" {
					tags = append(tags, strings.ToLower(p))
				}
			}
		}

		doc := Document{
			ID:      id,
			Title:   title,
			Content: content,
			Type:    docType,
			Source:  "configmap:" + key,
			Tags:    tags,
		}

		docs = append(docs, doc)
		l.logger.Debug("loaded document from ConfigMap",
			zap.String("key", key),
			zap.String("id", doc.ID),
			zap.String("type", string(doc.Type)),
			zap.Int("contentBytes", len(content)),
		)
	}

	l.logger.Info("loaded documents from ConfigMap",
		zap.Int("total", len(data)),
		zap.Int("loaded", len(docs)),
	)
	return docs, nil
}
