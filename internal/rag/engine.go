// Package rag provides Retrieval-Augmented Generation (RAG) capabilities for
// kube-diagnose. This file implements the Engine, the central orchestrator
// that ties together embedding, vector storage, and retrieval to augment LLM
// prompts with semantically relevant context.
package rag

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/zap"
)

// -----------------------------------------------------------------------------
// Collection names
// -----------------------------------------------------------------------------

// The Engine maintains three Qdrant collections:
//   - runbooks:  indexed runbook / guide documents
//   - incidents: resolved incident records for future retrieval
//   - metadata:  auxiliary metadata documents (reserved for future use)
const (
	collectionRunbooks  = "runbooks"
	collectionIncidents = "incidents"
	collectionMetadata  = "metadata"
)

// indexBatchSize is the maximum number of documents submitted to Qdrant per
// upsert call.
const indexBatchSize = 20

// -----------------------------------------------------------------------------
// RetrievalResult
// -----------------------------------------------------------------------------

// RetrievalResult pairs a retrieved Document with its similarity score and the
// Qdrant collection it was retrieved from.
type RetrievalResult struct {
	// Score is the normalised similarity score in [0.0, 1.0].
	Score float64

	// Document is the retrieved document or chunk.
	Document Document

	// Source identifies which collection this result came from
	// (e.g. "runbooks", "incidents", "metadata").
	Source string
}

// -----------------------------------------------------------------------------
// Engine
// -----------------------------------------------------------------------------

// Engine orchestrates document indexing and semantic retrieval. It embeds
// text using the configured Embedder, stores vectors in Qdrant, and retrieves
// the most relevant documents for a given query to be injected as context into
// an LLM prompt.
type Engine struct {
	embedder            Embedder
	qdrant              *QdrantClient
	logger              *zap.Logger
	collectionRunbooks  string
	collectionIncidents string
	collectionMetadata  string
}

// NewEngine constructs a Engine.
//
// embedder is used for all Embed calls; it must not be nil.
// qdrant is the vector store client; it must not be nil.
func NewEngine(embedder Embedder, qdrant *QdrantClient, logger *zap.Logger) *Engine {
	return &Engine{
		embedder:            embedder,
		qdrant:              qdrant,
		logger:              logger.With(zap.String("component", "rag_engine")),
		collectionRunbooks:  collectionRunbooks,
		collectionIncidents: collectionIncidents,
		collectionMetadata:  collectionMetadata,
	}
}

// -----------------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------------

// Initialize ensures that all three Qdrant collections exist with the correct
// vector dimensionality. It must be called once before IndexDocuments or
// Retrieve. It is idempotent — repeated calls are safe.
func (e *Engine) Initialize(ctx context.Context, dimensions int) error {
	if dimensions <= 0 {
		dimensions = e.embedder.Dimensions()
	}

	collections := []string{
		e.collectionRunbooks,
		e.collectionIncidents,
		e.collectionMetadata,
	}

	for _, name := range collections {
		if err := e.qdrant.EnsureCollection(ctx, name, dimensions); err != nil {
			return fmt.Errorf("initialize collection %q: %w", name, err)
		}
	}

	e.logger.Info("RAG engine initialised",
		zap.Strings("collections", collections),
		zap.Int("dimensions", dimensions),
	)
	return nil
}

// -----------------------------------------------------------------------------
// Indexing
// -----------------------------------------------------------------------------

// IndexDocuments embeds each document and upserts it into the runbooks
// collection. Documents are processed in batches of indexBatchSize to avoid
// overwhelming the Qdrant write path.
//
// A per-document embedding failure does not abort the entire operation; the
// document is skipped and the error is logged. The caller receives an error only
// if all documents fail.
func (e *Engine) IndexDocuments(ctx context.Context, docs []Document) error {
	if len(docs) == 0 {
		return nil
	}

	var (
		successCount int
		skipCount    int
	)
	batch := make([]QdrantPoint, 0, indexBatchSize)

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := e.qdrant.Upsert(ctx, e.collectionRunbooks, batch); err != nil {
			return fmt.Errorf("upsert batch to runbooks: %w", err)
		}
		successCount += len(batch)
		batch = batch[:0]
		return nil
	}

	for i := range docs {
		doc := docs[i]

		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled during IndexDocuments: %w", err)
		}

		vec, err := e.embedder.Embed(ctx, doc.Content)
		if err != nil {
			e.logger.Warn("failed to embed document, skipping",
				zap.String("docID", doc.ID),
				zap.String("title", doc.Title),
				zap.Error(err),
			)
			skipCount++
			continue
		}

		point := QdrantPoint{
			ID:     docUUID(doc.ID),
			Vector: vec,
			Payload: map[string]interface{}{
				"id":      doc.ID,
				"title":   doc.Title,
				"content": doc.Content,
				"type":    string(doc.Type),
				"source":  doc.Source,
				"tags":    doc.Tags,
			},
		}
		batch = append(batch, point)

		if len(batch) >= indexBatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}

	// Flush any remaining points in the last partial batch.
	if err := flush(); err != nil {
		return err
	}

	e.logger.Info("document indexing complete",
		zap.Int("indexed", successCount),
		zap.Int("skipped", skipCount),
		zap.Int("total", len(docs)),
	)

	if successCount == 0 && len(docs) > 0 {
		return fmt.Errorf("failed to index any of the %d provided documents", len(docs))
	}
	return nil
}

// IndexResolvedIncident embeds a resolved incident record and stores it in the
// incidents collection. Future queries that resemble the incident pattern will
// retrieve this record as additional context, enabling the LLM to reference
// real past resolutions.
//
// fingerprint is the alert fingerprint; pattern is a textual description of the
// failure pattern; rootCause and resolution are the post-incident findings.
func (e *Engine) IndexResolvedIncident(
	ctx context.Context,
	fingerprint, pattern, rootCause, resolution, namespace string,
) error {
	// Construct a rich text representation that captures all facets of the
	// incident for better semantic recall.
	incidentText := buildIncidentText(pattern, rootCause, resolution, namespace)

	vec, err := e.embedder.Embed(ctx, incidentText)
	if err != nil {
		return fmt.Errorf("embed resolved incident %q: %w", fingerprint, err)
	}

	point := QdrantPoint{
		ID:     docUUID(fingerprint),
		Vector: vec,
		Payload: map[string]interface{}{
			"id":          fingerprint,
			"title":       fmt.Sprintf("Resolved incident: %s", pattern),
			"content":     incidentText,
			"type":        "incident",
			"source":      "incident_history",
			"fingerprint": fingerprint,
			"pattern":     pattern,
			"root_cause":  rootCause,
			"resolution":  resolution,
			"namespace":   namespace,
		},
	}

	if err := e.qdrant.Upsert(ctx, e.collectionIncidents, []QdrantPoint{point}); err != nil {
		return fmt.Errorf("upsert resolved incident %q: %w", fingerprint, err)
	}

	e.logger.Info("indexed resolved incident",
		zap.String("fingerprint", fingerprint),
		zap.String("namespace", namespace),
	)
	return nil
}

// buildIncidentText formats a resolved incident as a rich text block for
// embedding. The format intentionally mirrors how a postmortem might be written
// to maximise semantic similarity with future related queries.
func buildIncidentText(pattern, rootCause, resolution, namespace string) string {
	return fmt.Sprintf(
		"Incident Pattern: %s\nNamespace: %s\nRoot Cause: %s\nResolution: %s",
		pattern, namespace, rootCause, resolution,
	)
}

// -----------------------------------------------------------------------------
// Retrieval
// -----------------------------------------------------------------------------

// Retrieve embeds the query string, searches all three collections, merges the
// results, and re-ranks them by descending score. It returns the top topK
// results along with the maximum confidence score (0.0–1.0).
//
// The confidence score is derived from Qdrant's cosine similarity score, which
// is already normalised to [0.0, 1.0] for cosine-distance collections.
//
// If topK ≤ 0 it defaults to 5.
func (e *Engine) Retrieve(ctx context.Context, query string, topK int) ([]RetrievalResult, float64, error) {
	if topK <= 0 {
		topK = 5
	}

	queryVec, err := e.embedder.Embed(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("embed query: %w", err)
	}

	// Search all three collections; failures in individual collections are
	// logged and treated as empty result sets so that the others can still
	// contribute.
	collections := []string{
		e.collectionRunbooks,
		e.collectionIncidents,
		e.collectionMetadata,
	}

	// We request more results per collection than topK so that the merge and
	// re-rank step has enough candidates to choose from.
	perCollectionLimit := topK * 2
	if perCollectionLimit < 5 {
		perCollectionLimit = 5
	}

	var allResults []RetrievalResult

	for _, col := range collections {
		searchResults, err := e.qdrant.Search(ctx, col, queryVec, perCollectionLimit)
		if err != nil {
			e.logger.Warn("search failed for collection, skipping",
				zap.String("collection", col),
				zap.Error(err),
			)
			continue
		}

		for _, sr := range searchResults {
			doc := documentFromPayload(sr.Payload)
			score := normaliseScore(sr.Score)

			allResults = append(allResults, RetrievalResult{
				Score:    score,
				Document: doc,
				Source:   col,
			})
		}
	}

	if len(allResults) == 0 {
		e.logger.Info("no results found across any collection",
			zap.String("query", truncate(query, 100)),
		)
		return nil, 0, nil
	}

	// Sort descending by score.
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].Score > allResults[j].Score
	})

	// Trim to topK.
	if len(allResults) > topK {
		allResults = allResults[:topK]
	}

	maxConfidence := 0.0
	if len(allResults) > 0 {
		maxConfidence = allResults[0].Score
	}

	e.logger.Info("retrieval complete",
		zap.String("query", truncate(query, 100)),
		zap.Int("results", len(allResults)),
		zap.Float64("maxConfidence", maxConfidence),
	)

	return allResults, maxConfidence, nil
}

// normaliseScore maps a Qdrant cosine similarity score to the [0.0, 1.0] range.
//
// For collections created with Cosine distance, Qdrant returns the raw dot
// product of the (normalised) query and stored vectors, which is already the
// cosine similarity in [−1.0, 1.0]. We linearly map this to [0.0, 1.0].
func normaliseScore(raw float64) float64 {
	// Map [-1, 1] → [0, 1].
	normalised := (raw + 1.0) / 2.0
	// Clamp to [0, 1] to guard against floating-point edge cases.
	if normalised < 0 {
		return 0
	}
	if normalised > 1 {
		return 1
	}
	return normalised
}

// documentFromPayload reconstructs a Document from a Qdrant point's payload map.
// Missing fields are silently defaulted to zero values.
func documentFromPayload(payload map[string]interface{}) Document {
	if payload == nil {
		return Document{}
	}

	getString := func(key string) string {
		v, _ := payload[key].(string)
		return v
	}

	getStringSlice := func(key string) []string {
		raw, ok := payload[key]
		if !ok {
			return nil
		}
		switch v := raw.(type) {
		case []string:
			return v
		case []interface{}:
			out := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
		return nil
	}

	docTypeRaw := getString("type")
	var docType DocumentType
	switch DocumentType(docTypeRaw) {
	case DocumentTypeRunbook, DocumentTypePostmortem, DocumentTypeGuide, "incident":
		docType = DocumentType(docTypeRaw)
	default:
		docType = DocumentTypeUnknown
	}

	return Document{
		ID:      getString("id"),
		Title:   getString("title"),
		Content: getString("content"),
		Type:    docType,
		Source:  getString("source"),
		Tags:    getStringSlice("tags"),
	}
}

// -----------------------------------------------------------------------------
// Context formatting
// -----------------------------------------------------------------------------

// FormatContext renders the retrieval results as a structured text block
// suitable for injection into an LLM system prompt or user message.
//
// The output is formatted as a numbered list where each entry includes its
// source category, score, title, and content.
func (e *Engine) FormatContext(results []RetrievalResult) string {
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder

	sb.WriteString("## Retrieved Context\n\n")
	sb.WriteString("The following documents were retrieved from the knowledge base " +
		"based on semantic similarity to your query:\n\n")

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("### [%d] %s\n", i+1, r.Document.Title))
		sb.WriteString(fmt.Sprintf("- **Source**: %s\n", r.Source))
		sb.WriteString(fmt.Sprintf("- **Type**: %s\n", string(r.Document.Type)))
		sb.WriteString(fmt.Sprintf("- **Relevance**: %.1f%%\n", r.Score*100))

		if len(r.Document.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("- **Tags**: %s\n", strings.Join(r.Document.Tags, ", ")))
		}

		sb.WriteString("\n")
		sb.WriteString(r.Document.Content)
		sb.WriteString("\n\n")

		if i < len(results)-1 {
			sb.WriteString("---\n\n")
		}
	}

	return sb.String()
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

// docUUID converts an arbitrary document ID string into a form acceptable as a
// Qdrant UUID point ID. Qdrant accepts UUID v4 strings. Since our document IDs
// are human-readable strings, we generate a deterministic UUID v5-style
// representation using a simple name-based hash.
//
// Implementation note: we use a UUID-shaped hex representation derived from the
// FNV-1a hash of the input string. This is not a true UUID v5 (which requires
// SHA-1) but is collision-resistant enough for operational use cases and avoids
// pulling in additional dependencies.
func docUUID(id string) string {
	// FNV-1a 128-bit hash (two 64-bit halves).
	const (
		offset64Hi uint64 = 0xcbf29ce484222325
		offset64Lo uint64 = 0x14c4b09d7afb5f99
		prime64    uint64 = 0x00000100000001B3
	)

	hi, lo := offset64Hi, offset64Lo
	for _, b := range []byte(id) {
		lo ^= uint64(b)
		lo *= prime64
		hi ^= uint64(b)
		hi *= prime64
	}

	// Format as a UUID: 8-4-4-4-12 hex characters.
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		hi>>32,
		(hi>>16)&0xFFFF,
		hi&0xFFFF,
		lo>>48,
		lo&0xFFFFFFFFFFFF,
	)
}

// truncate shortens a string to at most maxLen characters, appending "…" if
// truncated. Used for log messages to avoid excessive line lengths.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "…"
}
