// Package rag provides Retrieval-Augmented Generation (RAG) capabilities for
// kube-diagnose. It handles document embedding, vector storage, and semantic
// retrieval to augment LLM prompts with relevant runbooks and past incidents.
package rag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	openai "github.com/sashabaranov/go-openai"
	"go.uber.org/zap"
)

// -----------------------------------------------------------------------------
// Embedder interface
// -----------------------------------------------------------------------------

// Embedder converts a text string into a dense vector representation.
// Implementations must be safe for concurrent use.
type Embedder interface {
	// Embed returns the vector embedding for the given text.
	Embed(ctx context.Context, text string) ([]float32, error)

	// Dimensions returns the size of the vectors produced by this embedder.
	Dimensions() int
}

// -----------------------------------------------------------------------------
// Retry helpers
// -----------------------------------------------------------------------------

const (
	maxRetries      = 3
	retryBaseDelay  = 500 * time.Millisecond
	retryMultiplier = 2.0
)

// withRetry executes fn up to maxRetries times with exponential backoff.
// It returns the last error encountered if all attempts fail.
func withRetry(ctx context.Context, logger *zap.Logger, operationName string, fn func() error) error {
	var lastErr error
	delay := retryBaseDelay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s: context cancelled before attempt %d: %w", operationName, attempt, err)
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		if attempt == maxRetries {
			break
		}

		logger.Warn("embedding attempt failed, retrying",
			zap.String("operation", operationName),
			zap.Int("attempt", attempt),
			zap.Int("maxAttempts", maxRetries),
			zap.Duration("retryDelay", delay),
			zap.Error(lastErr),
		)

		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: context cancelled during retry backoff: %w", operationName, ctx.Err())
		case <-time.After(delay):
		}

		delay = time.Duration(float64(delay) * retryMultiplier)
	}

	return fmt.Errorf("%s: all %d attempts failed, last error: %w", operationName, maxRetries, lastErr)
}

// -----------------------------------------------------------------------------
// OpenAIEmbedder
// -----------------------------------------------------------------------------

// defaultOpenAIModel is used when no model is explicitly specified.
const defaultOpenAIModel = string(openai.SmallEmbedding3)

// openAIModelDimensions maps known OpenAI embedding models to their vector
// dimensionality. The text-embedding-3-* models support custom dimensions, but
// we default to their full size here.
var openAIModelDimensions = map[string]int{
	string(openai.SmallEmbedding3): 1536,
	string(openai.LargeEmbedding3): 3072,
	string(openai.AdaEmbeddingV2):  1536,
}

// OpenAIEmbedder wraps the OpenAI embeddings API.
type OpenAIEmbedder struct {
	client     *openai.Client
	model      openai.EmbeddingModel
	dimensions int
	logger     *zap.Logger
}

// NewOpenAIEmbedder constructs an OpenAIEmbedder.
// If model is empty the default model (text-embedding-3-small) is used.
func NewOpenAIEmbedder(apiKey, model string, logger *zap.Logger) *OpenAIEmbedder {
	if model == "" {
		model = defaultOpenAIModel
	}

	dims, ok := openAIModelDimensions[model]
	if !ok {
		// Unknown model — assume the default model's dimensions. Callers
		// that use a custom dimension via the API parameter would need their
		// own adapter.
		dims = openAIModelDimensions[defaultOpenAIModel]
		logger.Warn("unknown OpenAI embedding model, assuming default dimensions",
			zap.String("model", model),
			zap.Int("assumedDimensions", dims),
		)
	}

	return &OpenAIEmbedder{
		client:     openai.NewClient(apiKey),
		model:      openai.EmbeddingModel(model),
		dimensions: dims,
		logger:     logger.With(zap.String("embedder", "openai"), zap.String("model", model)),
	}
}

// Embed returns the vector embedding for text using the OpenAI API.
// It retries up to 3 times with exponential backoff on transient errors.
func (e *OpenAIEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	var result []float32

	err := withRetry(ctx, e.logger, "openai.Embed", func() error {
		resp, err := e.client.CreateEmbeddings(ctx, openai.EmbeddingRequestStrings{
			Input: []string{text},
			Model: e.model,
		})
		if err != nil {
			return fmt.Errorf("openai CreateEmbeddings: %w", err)
		}
		if len(resp.Data) == 0 {
			return fmt.Errorf("openai returned empty embedding data")
		}

		raw := resp.Data[0].Embedding
		result = make([]float32, len(raw))
		for i, v := range raw {
			result[i] = float32(v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	e.logger.Debug("embedded text via OpenAI",
		zap.Int("textLen", len(text)),
		zap.Int("dims", len(result)),
	)
	return result, nil
}

// Dimensions returns the number of dimensions in the embedding vectors.
func (e *OpenAIEmbedder) Dimensions() int { return e.dimensions }

// -----------------------------------------------------------------------------
// OllamaEmbedder
// -----------------------------------------------------------------------------

const (
	defaultOllamaModel     = "nomic-embed-text"
	defaultOllamaDimension = 768
)

// ollamaEmbedRequest is the JSON body for POST /api/embeddings.
type ollamaEmbedRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// ollamaEmbedResponse is the JSON response body from /api/embeddings.
type ollamaEmbedResponse struct {
	Embedding []float32 `json:"embedding"`
}

// OllamaEmbedder calls a locally-running Ollama instance to produce embeddings.
type OllamaEmbedder struct {
	endpoint   string // e.g. "http://localhost:11434"
	model      string
	dimensions int
	httpClient *http.Client
	logger     *zap.Logger
}

// NewOllamaEmbedder constructs an OllamaEmbedder.
// endpoint is the base URL of the Ollama server (e.g. "http://localhost:11434").
// If model is empty the default model (nomic-embed-text) is used.
func NewOllamaEmbedder(endpoint, model string, logger *zap.Logger) *OllamaEmbedder {
	if model == "" {
		model = defaultOllamaModel
	}

	return &OllamaEmbedder{
		endpoint: endpoint,
		model:    model,
		// Ollama does not expose per-model dimension metadata via a simple API;
		// we default to nomic-embed-text's 768 dimensions. Callers embedding
		// with a different model should provide the correct value if they need
		// strict validation downstream.
		dimensions: defaultOllamaDimension,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger.With(zap.String("embedder", "ollama"), zap.String("model", model)),
	}
}

// Embed returns the vector embedding for text by calling the Ollama HTTP API.
// It retries up to 3 times with exponential backoff on transient errors.
func (e *OllamaEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	var result []float32

	err := withRetry(ctx, e.logger, "ollama.Embed", func() error {
		body, err := json.Marshal(ollamaEmbedRequest{
			Model:  e.model,
			Prompt: text,
		})
		if err != nil {
			// Marshalling failure is not transient; stop retrying.
			return fmt.Errorf("marshal ollama request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint+"/api/embeddings", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create ollama HTTP request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := e.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("ollama HTTP request: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(raw))
		}

		var embedResp ollamaEmbedResponse
		if err := json.NewDecoder(resp.Body).Decode(&embedResp); err != nil {
			return fmt.Errorf("decode ollama response: %w", err)
		}
		if len(embedResp.Embedding) == 0 {
			return fmt.Errorf("ollama returned empty embedding")
		}

		result = embedResp.Embedding
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Update cached dimensions from actual response (helpful for non-default models).
	if len(result) != e.dimensions {
		e.logger.Info("ollama embedding dimensions differ from default, updating cached value",
			zap.Int("expected", e.dimensions),
			zap.Int("actual", len(result)),
		)
		e.dimensions = len(result)
	}

	e.logger.Debug("embedded text via Ollama",
		zap.Int("textLen", len(text)),
		zap.Int("dims", len(result)),
	)
	return result, nil
}

// Dimensions returns the number of dimensions in the embedding vectors.
func (e *OllamaEmbedder) Dimensions() int { return e.dimensions }

// -----------------------------------------------------------------------------
// Factory
// -----------------------------------------------------------------------------

// NewEmbedder constructs an Embedder based on the given provider name.
//
// provider must be one of "openai" or "ollama".
//
//   - For "openai": apiKey and model are used. model defaults to text-embedding-3-small.
//   - For "ollama": endpoint and model are used. model defaults to nomic-embed-text.
//     endpoint defaults to "http://localhost:11434".
func NewEmbedder(provider, apiKey, model, endpoint string, logger *zap.Logger) (Embedder, error) {
	switch provider {
	case "openai":
		if apiKey == "" {
			return nil, fmt.Errorf("openai embedder requires a non-empty apiKey")
		}
		return NewOpenAIEmbedder(apiKey, model, logger), nil

	case "ollama":
		if endpoint == "" {
			endpoint = "http://localhost:11434"
		}
		return NewOllamaEmbedder(endpoint, model, logger), nil

	default:
		return nil, fmt.Errorf("unsupported embedder provider %q: must be one of [openai, ollama]", provider)
	}
}

// -----------------------------------------------------------------------------
