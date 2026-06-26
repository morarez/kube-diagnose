package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// geminiRequest is the payload for the Gemini generateContent API.
type geminiRequest struct {
	Contents          []geminiContent   `json:"contents"`
	SystemInstruction *geminiContent    `json:"systemInstruction,omitempty"`
	GenerationConfig  *generationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type generationConfig struct {
	ResponseMIMEType string  `json:"responseMimeType,omitempty"`
	Temperature      float64 `json:"temperature,omitempty"`
	MaxOutputTokens  int     `json:"maxOutputTokens,omitempty"`
}

// geminiResponse is the schema for the Gemini generateContent API response.
type geminiResponse struct {
	Candidates    []geminiCandidate `json:"candidates"`
	UsageMetadata *usageMetadata    `json:"usageMetadata,omitempty"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason"`
}

type usageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// GoogleProvider implements LLMProvider using the Google Gemini REST API.
type GoogleProvider struct {
	apiKey     string
	model      string
	maxTokens  int
	httpClient *http.Client
	logger     *zap.Logger
}

// NewGoogleProvider creates a GoogleProvider.
func NewGoogleProvider(apiKey, model string, maxTokens int, logger *zap.Logger) *GoogleProvider {
	if model == "" {
		model = "gemini-1.5-flash"
	}
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	return &GoogleProvider{
		apiKey:     apiKey,
		model:      model,
		maxTokens:  maxTokens,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

// Name implements LLMProvider.
func (p *GoogleProvider) Name() string { return "google" }

// Analyze implements LLMProvider.
func (p *GoogleProvider) Analyze(ctx context.Context, prompt string) (*AnalysisResult, error) {
	systemMsg, userMsg := splitPrompt(prompt)

	reqPayload := geminiRequest{
		Contents: []geminiContent{
			{
				Role: "user",
				Parts: []geminiPart{
					{Text: userMsg},
				},
			},
		},
		GenerationConfig: &generationConfig{
			ResponseMIMEType: "application/json",
			Temperature:      0.2,
			MaxOutputTokens:  p.maxTokens,
		},
	}

	if systemMsg != "" {
		reqPayload.SystemInstruction = &geminiContent{
			Parts: []geminiPart{
				{Text: systemMsg},
			},
		}
	}

	url := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		p.model,
		p.apiKey,
	)

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("marshal gemini request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create gemini request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.doWithRateLimitRetry(req)
	if err != nil {
		return nil, fmt.Errorf("gemini api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini api returned status %d", resp.StatusCode)
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, fmt.Errorf("decode gemini response: %w", err)
	}

	if len(geminiResp.Candidates) == 0 {
		return nil, errors.New("gemini returned no candidates")
	}

	candidate := geminiResp.Candidates[0]
	if len(candidate.Content.Parts) == 0 {
		return nil, errors.New("gemini candidate has no parts")
	}

	raw := candidate.Content.Parts[0].Text
	p.logger.Debug("gemini raw response", zap.String("model", p.model))

	result, err := ParseAnalysisResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse gemini response: %w", err)
	}

	if geminiResp.UsageMetadata != nil {
		result.TokensUsed = geminiResp.UsageMetadata.TotalTokenCount
	}
	result.AnalysisSource = p.Name()

	return result, nil
}

func (p *GoogleProvider) doWithRateLimitRetry(req *http.Request) (*http.Response, error) {
	const rateLimitBackoff = 60 * time.Second

	cloneReq := req.Clone(req.Context())
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		cloneReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	resp, err := p.httpClient.Do(req)
	if err == nil && resp.StatusCode != http.StatusTooManyRequests {
		return resp, nil
	}

	if err == nil {
		_ = resp.Body.Close()
	}

	p.logger.Warn("gemini rate limited, backing off before retry",
		zap.Duration("backoff", rateLimitBackoff),
	)

	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-time.After(rateLimitBackoff):
	}

	resp, err = p.httpClient.Do(cloneReq)
	if err != nil {
		return nil, fmt.Errorf("gemini retry after rate limit: %w", err)
	}
	return resp, nil
}
