// Package rag provides Retrieval-Augmented Generation (RAG) capabilities for
// kube-diagnose. This file contains the Qdrant HTTP client used to manage
// vector collections, upsert embeddings, and run similarity searches.
package rag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// -----------------------------------------------------------------------------
// Domain types
// -----------------------------------------------------------------------------

// QdrantPoint represents a single vector point to be stored in Qdrant.
// ID must be a valid UUID v4 string; Qdrant only accepts UUID or unsigned-integer IDs.
type QdrantPoint struct {
	// ID is a UUID v4 string that uniquely identifies the point.
	ID string `json:"id"`
	// Vector is the embedding associated with this point.
	Vector []float32 `json:"vector"`
	// Payload holds arbitrary metadata (e.g. document title, source, tags).
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// SearchResult is a single item returned by a Qdrant vector search.
type SearchResult struct {
	// ID is the UUID of the matched point.
	ID string `json:"id"`
	// Score is the similarity score (dot-product for cosine-indexed collections).
	Score float64 `json:"score"`
	// Payload is the metadata stored alongside the vector.
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// -----------------------------------------------------------------------------
// Internal Qdrant API request / response types
// -----------------------------------------------------------------------------

// qdrantCollectionConfig mirrors the subset of Qdrant's PUT /collections/{name}
// body that we need to create a collection with cosine distance.
type qdrantCollectionConfig struct {
	Vectors qdrantVectorParams `json:"vectors"`
}

type qdrantVectorParams struct {
	Size     int    `json:"size"`
	Distance string `json:"distance"`
}

// qdrantUpsertBody is the request body for PUT /collections/{name}/points.
type qdrantUpsertBody struct {
	Points []qdrantPointWire `json:"points"`
}

// qdrantPointWire is the wire representation of a QdrantPoint (ID as string).
type qdrantPointWire struct {
	ID      string                 `json:"id"`
	Vector  []float32              `json:"vector"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// qdrantSearchBody is the request body for POST /collections/{name}/points/search.
type qdrantSearchBody struct {
	Vector      []float32 `json:"vector"`
	Limit       int       `json:"limit"`
	WithPayload bool      `json:"with_payload"`
}

// qdrantSearchResponse is the response body from Qdrant's search endpoint.
type qdrantSearchResponse struct {
	Result []qdrantScoredPoint `json:"result"`
	Status string              `json:"status"`
}

// qdrantScoredPoint is a single result from Qdrant's search.
type qdrantScoredPoint struct {
	ID      interface{}            `json:"id"`
	Score   float64                `json:"score"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// qdrantCollectionInfoResponse is the response body from GET /collections/{name}.
type qdrantCollectionInfoResponse struct {
	Result *qdrantCollectionInfo `json:"result"`
	Status string                `json:"status"`
}

type qdrantCollectionInfo struct {
	Status string `json:"status"`
}

// qdrantGenericResponse captures the generic "status" field present in most
// Qdrant write responses.
type qdrantGenericResponse struct {
	Status string      `json:"status"`
	Result interface{} `json:"result,omitempty"`
}

// -----------------------------------------------------------------------------
// QdrantClient
// -----------------------------------------------------------------------------

// QdrantClient is a lightweight HTTP client for the Qdrant vector database REST
// API. It intentionally avoids the gRPC client to keep the dependency tree
// minimal and to work across restricted network environments.
type QdrantClient struct {
	host             string
	httpPort         int
	apiKey           string
	httpClient       *http.Client
	collectionPrefix string
	logger           *zap.Logger
}

// NewQdrantClient constructs a QdrantClient.
//
//   - host: hostname or IP of the Qdrant server (e.g. "localhost").
//   - httpPort: REST API port (default Qdrant: 6333).
//   - apiKey: optional Qdrant API key; pass "" for unauthenticated clusters.
//   - collectionPrefix: prefix prepended to every collection name to support
//     multi-tenancy within a shared Qdrant instance.
func NewQdrantClient(host string, httpPort int, apiKey, collectionPrefix string, logger *zap.Logger) *QdrantClient {
	return &QdrantClient{
		host:             host,
		httpPort:         httpPort,
		apiKey:           apiKey,
		collectionPrefix: collectionPrefix,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger.With(
			zap.String("component", "qdrant"),
			zap.String("host", host),
			zap.Int("httpPort", httpPort),
		),
	}
}

// baseURL returns the root REST API URL including scheme, host, and port.
func (c *QdrantClient) baseURL() string {
	return fmt.Sprintf("http://%s:%d", c.host, c.httpPort)
}

// prefixedCollection returns the full collection name with the configured prefix.
func (c *QdrantClient) prefixedCollection(name string) string {
	if c.collectionPrefix == "" {
		return name
	}
	return c.collectionPrefix + "_" + name
}

// doRequest executes an HTTP request, attaches auth headers, and returns the
// raw response body together with the HTTP status code.
// The caller is responsible for closing the body.
func (c *QdrantClient) doRequest(ctx context.Context, method, url string, reqBody interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("marshal request body for %s %s: %w", method, url, err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, url, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("api-key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP %s %s: %w", method, url, err)
	}
	return resp, nil
}

// readAndClose reads the full response body and closes it. It returns an error
// if the HTTP status is not one of the provided acceptable codes, with the first
// 4 KiB of the body included in the error message for diagnostics.
func readAndClose(resp *http.Response, acceptableCodes ...int) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	for _, code := range acceptableCodes {
		if resp.StatusCode == code {
			return body, nil
		}
	}
	snippet := string(body)
	if len(snippet) > 4096 {
		snippet = snippet[:4096] + "…"
	}
	return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, snippet)
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

// EnsureCollection creates the named collection in Qdrant if it does not already
// exist. The collection is configured with cosine distance and the given vector
// dimensionality. It is safe to call on an existing collection.
func (c *QdrantClient) EnsureCollection(ctx context.Context, name string, dimensions int) error {
	fullName := c.prefixedCollection(name)
	checkURL := fmt.Sprintf("%s/collections/%s", c.baseURL(), fullName)

	// Check whether the collection already exists.
	resp, err := c.doRequest(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return fmt.Errorf("check collection %q existence: %w", fullName, err)
	}

	if resp.StatusCode == http.StatusOK {
		body, err := readAndClose(resp, http.StatusOK)
		if err != nil {
			return fmt.Errorf("read collection info response for %q: %w", fullName, err)
		}
		var info qdrantCollectionInfoResponse
		if jsonErr := json.Unmarshal(body, &info); jsonErr == nil && info.Result != nil {
			c.logger.Debug("collection already exists, skipping creation",
				zap.String("collection", fullName),
			)
			return nil
		}
	} else {
		resp.Body.Close() //nolint:errcheck
	}

	// Create the collection.
	createURL := fmt.Sprintf("%s/collections/%s", c.baseURL(), fullName)
	createBody := qdrantCollectionConfig{
		Vectors: qdrantVectorParams{
			Size:     dimensions,
			Distance: "Cosine",
		},
	}

	createResp, err := c.doRequest(ctx, http.MethodPut, createURL, createBody)
	if err != nil {
		return fmt.Errorf("create collection %q: %w", fullName, err)
	}

	rawBody, err := readAndClose(createResp, http.StatusOK, http.StatusCreated)
	if err != nil {
		return fmt.Errorf("create collection %q: %w", fullName, err)
	}

	var genericResp qdrantGenericResponse
	if jsonErr := json.Unmarshal(rawBody, &genericResp); jsonErr != nil {
		return fmt.Errorf("decode create-collection response for %q: %w", fullName, jsonErr)
	}

	c.logger.Info("collection created",
		zap.String("collection", fullName),
		zap.Int("dimensions", dimensions),
		zap.String("distance", "Cosine"),
	)
	return nil
}

// Upsert inserts or updates the given points in the specified collection.
// The collection name is prefixed automatically.
func (c *QdrantClient) Upsert(ctx context.Context, collection string, points []QdrantPoint) error {
	if len(points) == 0 {
		return nil
	}

	fullName := c.prefixedCollection(collection)
	url := fmt.Sprintf("%s/collections/%s/points", c.baseURL(), fullName)

	wire := make([]qdrantPointWire, len(points))
	for i, p := range points {
		wire[i] = qdrantPointWire(p)
	}

	resp, err := c.doRequest(ctx, http.MethodPut, url, qdrantUpsertBody{Points: wire})
	if err != nil {
		return fmt.Errorf("upsert %d points to collection %q: %w", len(points), fullName, err)
	}

	if _, err := readAndClose(resp, http.StatusOK); err != nil {
		return fmt.Errorf("upsert %d points to collection %q: %w", len(points), fullName, err)
	}

	c.logger.Debug("upserted points to Qdrant",
		zap.String("collection", fullName),
		zap.Int("count", len(points)),
	)
	return nil
}

// Search queries the given collection for the nearest neighbours of vector,
// returning at most limit results. The collection name is prefixed automatically.
func (c *QdrantClient) Search(ctx context.Context, collection string, vector []float32, limit int) ([]SearchResult, error) {
	fullName := c.prefixedCollection(collection)
	url := fmt.Sprintf("%s/collections/%s/points/search", c.baseURL(), fullName)

	searchBody := qdrantSearchBody{
		Vector:      vector,
		Limit:       limit,
		WithPayload: true,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, url, searchBody)
	if err != nil {
		return nil, fmt.Errorf("search collection %q: %w", fullName, err)
	}

	rawBody, err := readAndClose(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("search collection %q: %w", fullName, err)
	}

	var searchResp qdrantSearchResponse
	if err := json.Unmarshal(rawBody, &searchResp); err != nil {
		return nil, fmt.Errorf("decode search response for collection %q: %w", fullName, err)
	}

	results := make([]SearchResult, 0, len(searchResp.Result))
	for _, sp := range searchResp.Result {
		// Qdrant may return the ID as a string or a number depending on the
		// point type. We normalise to string for consistency.
		idStr := fmt.Sprintf("%v", sp.ID)
		results = append(results, SearchResult{
			ID:      idStr,
			Score:   sp.Score,
			Payload: sp.Payload,
		})
	}

	c.logger.Debug("search completed",
		zap.String("collection", fullName),
		zap.Int("returned", len(results)),
	)
	return results, nil
}

// HealthCheck verifies that the Qdrant instance is reachable and healthy by
// calling the /healthz endpoint.
func (c *QdrantClient) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/healthz", c.baseURL())

	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("qdrant health check: %w", err)
	}

	if _, err := readAndClose(resp, http.StatusOK); err != nil {
		return fmt.Errorf("qdrant health check: %w", err)
	}

	c.logger.Debug("qdrant health check passed")
	return nil
}
