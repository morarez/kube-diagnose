// Package rag provides Retrieval-Augmented Generation (RAG) capabilities for
// kube-diagnose. It handles document embedding, vector storage, and semantic
// retrieval to augment LLM prompts with relevant runbooks and past incidents.
package rag

import (
	"context"
	"fmt"
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
// Factory
// -----------------------------------------------------------------------------

// NewEmbedder constructs an Embedder based on the given provider name.
//
// provider must be "openai".
//
//   - For "openai": apiKey and model are used. model defaults to text-embedding-3-small.
func NewEmbedder(provider, apiKey, model, _ string, logger *zap.Logger) (Embedder, error) {
	switch provider {
	case "openai":
		if apiKey == "" {
			return nil, fmt.Errorf("openai embedder requires a non-empty apiKey")
		}
		return NewOpenAIEmbedder(apiKey, model, logger), nil

	default:
		return nil, fmt.Errorf("unsupported embedder provider %q: must be one of [openai]", provider)
	}
}

// -----------------------------------------------------------------------------
