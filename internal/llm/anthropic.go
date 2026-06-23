package llm

import (
	"context"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"go.uber.org/zap"
)

// AnthropicProvider implements LLMProvider using the Anthropic Messages API.
// It is safe for concurrent use.
type AnthropicProvider struct {
	client    *anthropic.Client
	model     string
	maxTokens int
	logger    *zap.Logger
}

// NewAnthropicProvider creates a ready-to-use AnthropicProvider.
//
//   - apiKey    – Anthropic API key (required)
//   - model     – model identifier; defaults to claude-3-5-haiku-latest if empty
//   - maxTokens – maximum completion tokens
//   - logger    – structured logger; must not be nil
func NewAnthropicProvider(apiKey, model string, maxTokens int, logger *zap.Logger) *AnthropicProvider {
	if model == "" {
		model = "claude-3-5-haiku-latest"
	}
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	c := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &AnthropicProvider{
		client:    &c,
		model:     model,
		maxTokens: maxTokens,
		logger:    logger,
	}
}

// Name implements LLMProvider.
func (p *AnthropicProvider) Name() string { return "anthropic" }

// Analyze implements LLMProvider. It sends the prompt as a user message to
// Anthropic's Messages endpoint with the system instructions extracted from the
// prompt header. Returns a parsed AnalysisResult.
func (p *AnthropicProvider) Analyze(ctx context.Context, prompt string) (*AnalysisResult, error) {
	systemMsg, userMsg := splitPrompt(prompt)

	params := anthropic.MessageNewParams{
		Model:     p.model,
		MaxTokens: int64(p.maxTokens),
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
		},
	}
	if systemMsg != "" {
		params.System = []anthropic.TextBlockParam{
			{Text: systemMsg},
		}
	}

	resp, err := p.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("anthropic messages.new: %w", err)
	}

	if len(resp.Content) == 0 {
		return nil, fmt.Errorf("anthropic returned empty content")
	}

	// Extract text from first content block.
	raw := ""
	for _, block := range resp.Content {
		if block.Type == "text" {
			raw = block.Text
			break
		}
	}
	if raw == "" {
		return nil, fmt.Errorf("anthropic response had no text block")
	}

	p.logger.Debug("anthropic raw response",
		zap.String("model", p.model),
		zap.Int("inputTokens", int(resp.Usage.InputTokens)),
		zap.Int("outputTokens", int(resp.Usage.OutputTokens)),
	)

	result, err := ParseAnalysisResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse anthropic response: %w", err)
	}

	result.TokensUsed = int(resp.Usage.InputTokens + resp.Usage.OutputTokens)
	result.AnalysisSource = p.Name()
	return result, nil
}
