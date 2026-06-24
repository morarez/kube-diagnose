package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	openai "github.com/sashabaranov/go-openai"
	"go.uber.org/zap"
)

// OpenAIProvider implements LLMProvider using the OpenAI chat-completions API.
// It is safe for concurrent use.
type OpenAIProvider struct {
	client      *openai.Client
	model       string
	maxTokens   int
	temperature float32
	logger      *zap.Logger
}

// NewOpenAIProvider creates a ready-to-use OpenAIProvider.
//
//   - apiKey    – OpenAI API key (required)
//   - model     – model identifier, e.g. "gpt-4o-mini" or "gpt-4o"
//   - maxTokens – upper bound on completion tokens (prompt tokens are separate)
//   - logger    – structured logger; must not be nil
//
// A default temperature of 0.2 is used to keep responses deterministic while
// still allowing some variation in phrasing.
func NewOpenAIProvider(apiKey, model string, maxTokens int, logger *zap.Logger) *OpenAIProvider {
	return NewOpenAIProviderWithEndpoint(apiKey, model, "", maxTokens, logger)
}

// NewOpenAIProviderWithEndpoint creates an OpenAIProvider targeting a custom BaseURL.
func NewOpenAIProviderWithEndpoint(apiKey, model, endpoint string, maxTokens int, logger *zap.Logger) *OpenAIProvider {
	config := openai.DefaultConfig(apiKey)
	if endpoint != "" {
		config.BaseURL = endpoint
	}
	return &OpenAIProvider{
		client:      openai.NewClientWithConfig(config),
		model:       model,
		maxTokens:   maxTokens,
		temperature: 0.2,
		logger:      logger,
	}
}

// Name implements LLMProvider.
func (p *OpenAIProvider) Name() string { return "openai" }

// Analyze implements LLMProvider. It sends the prompt as a two-message
// conversation (system + user) to the chat-completions endpoint and returns a
// parsed AnalysisResult.
//
// If the API responds with HTTP 429 (rate-limited), the call is retried once
// after a 60-second back-off. All other errors are returned immediately.
func (p *OpenAIProvider) Analyze(ctx context.Context, prompt string) (*AnalysisResult, error) {
	// Split the prompt into the system and user sections that BuildAnalysisPrompt
	// separated with a sentinel header.
	systemMsg, userMsg := splitPrompt(prompt)

	req := openai.ChatCompletionRequest{
		Model:       p.model,
		MaxTokens:   p.maxTokens,
		Temperature: p.temperature,
		// Ask the model to emit JSON; supported on GPT-4o and GPT-4o-mini.
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		},
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: systemMsg,
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: userMsg,
			},
		},
	}

	resp, err := p.doWithRateLimitRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("openai chat completion: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, errors.New("openai returned no choices")
	}

	raw := resp.Choices[0].Message.Content
	p.logger.Debug("openai raw response",
		zap.String("model", p.model),
		zap.Int("prompt_tokens", resp.Usage.PromptTokens),
		zap.Int("completion_tokens", resp.Usage.CompletionTokens),
	)

	result, err := ParseAnalysisResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse openai response: %w", err)
	}

	result.TokensUsed = resp.Usage.TotalTokens
	result.AnalysisSource = p.Name()
	return result, nil
}

// doWithRateLimitRetry executes the chat completion request. On an HTTP 429
// response, it waits rateLimitBackoff before making exactly one retry. All
// other errors are returned immediately.
func (p *OpenAIProvider) doWithRateLimitRetry(
	ctx context.Context,
	req openai.ChatCompletionRequest,
) (openai.ChatCompletionResponse, error) {
	const rateLimitBackoff = 60 * time.Second

	resp, err := p.client.CreateChatCompletion(ctx, req)
	if err == nil {
		return resp, nil
	}

	// Inspect the error for an HTTP 429 status.
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatusCode != http.StatusTooManyRequests {
		return openai.ChatCompletionResponse{}, err
	}

	p.logger.Warn("openai rate limited, backing off before retry",
		zap.Duration("backoff", rateLimitBackoff),
	)

	select {
	case <-ctx.Done():
		return openai.ChatCompletionResponse{}, ctx.Err()
	case <-time.After(rateLimitBackoff):
	}

	// Single retry after backoff.
	resp, err = p.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return openai.ChatCompletionResponse{}, fmt.Errorf("openai retry after rate limit: %w", err)
	}
	return resp, nil
}

// splitPrompt divides the combined prompt string produced by BuildAnalysisPrompt
// into the system and user sub-strings that the chat-completions API expects as
// separate message roles.
//
// The prompt format uses "### SYSTEM\n" and "### USER\n" sentinel headers.
// If the sentinel is absent the entire prompt is treated as the user message.
func splitPrompt(prompt string) (system, user string) {
	const (
		sysHeader  = "### SYSTEM\n"
		userHeader = "### USER\n"
	)

	sysIdx := indexOf(prompt, sysHeader)
	userIdx := indexOf(prompt, userHeader)

	if sysIdx == -1 {
		return "", prompt
	}
	if userIdx == -1 {
		// Only a system section.
		return prompt[sysIdx+len(sysHeader):], ""
	}

	system = prompt[sysIdx+len(sysHeader) : userIdx]
	user = prompt[userIdx+len(userHeader):]
	return trimRight(system), user
}

// indexOf returns the byte index of sub in s, or -1 if not found.
func indexOf(s, sub string) int {
	i := 0
	for i+len(sub) <= len(s) {
		if s[i:i+len(sub)] == sub {
			return i
		}
		i++
	}
	return -1
}

// trimRight removes trailing whitespace from s.
func trimRight(s string) string {
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[:end]
}
