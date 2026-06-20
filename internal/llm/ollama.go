package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// OllamaProvider implements LLMProvider using the Ollama local inference server.
// It communicates via Ollama's HTTP API using only the standard library.
// It is safe for concurrent use.
type OllamaProvider struct {
	endpoint   string
	model      string
	maxTokens  int
	httpClient *http.Client
	logger     *zap.Logger
}

// NewOllamaProvider creates a ready-to-use OllamaProvider.
//
//   - endpoint  – Ollama base URL, e.g. "http://localhost:11434"
//   - model     – model tag, e.g. "llama3.2"; defaults to "llama3.2" if empty
//   - maxTokens – max tokens for the response; passed as num_predict
//   - logger    – structured logger; must not be nil
func NewOllamaProvider(endpoint, model string, maxTokens int, logger *zap.Logger) *OllamaProvider {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.2"
	}
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	return &OllamaProvider{
		endpoint:  strings.TrimRight(endpoint, "/"),
		model:     model,
		maxTokens: maxTokens,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute, // local inference can be slow
		},
		logger: logger,
	}
}

// Name implements LLMProvider.
func (p *OllamaProvider) Name() string { return "ollama" }

// ollamaChatRequest is the request body for /api/chat.
type ollamaChatRequest struct {
	Model    string              `json:"model"`
	Messages []ollamaChatMessage `json:"messages"`
	Stream   bool                `json:"stream"`
	Options  ollamaOptions       `json:"options"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	NumPredict  int     `json:"num_predict"`
	Temperature float64 `json:"temperature"`
}

// ollamaChatResponse is the response body from /api/chat (non-streaming).
type ollamaChatResponse struct {
	Message ollamaChatMessage `json:"message"`
	Done    bool              `json:"done"`
}

// Analyze implements LLMProvider.
func (p *OllamaProvider) Analyze(ctx context.Context, prompt string) (*AnalysisResult, error) {
	systemMsg, userMsg := splitPrompt(prompt)

	messages := make([]ollamaChatMessage, 0, 2)
	if systemMsg != "" {
		messages = append(messages, ollamaChatMessage{Role: "system", Content: systemMsg})
	}
	messages = append(messages, ollamaChatMessage{Role: "user", Content: userMsg})

	reqBody := ollamaChatRequest{
		Model:    p.model,
		Messages: messages,
		Stream:   false,
		Options: ollamaOptions{
			NumPredict:  p.maxTokens,
			Temperature: 0.2,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal ollama request: %w", err)
	}

	url := p.endpoint + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create ollama request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama http call: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return nil, fmt.Errorf("ollama returned HTTP %d: %s", httpResp.StatusCode, string(body))
	}

	var chatResp ollamaChatResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("decode ollama response: %w", err)
	}

	raw := chatResp.Message.Content
	p.logger.Debug("ollama raw response",
		zap.String("model", p.model),
		zap.Int("responseLen", len(raw)),
	)

	result, err := ParseAnalysisResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse ollama response: %w", err)
	}
	result.AnalysisSource = p.Name()
	return result, nil
}
