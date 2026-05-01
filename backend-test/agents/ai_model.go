package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────
// AI Model — wraps the Anthropic Messages API dcn vdnf,,m
// ─────────────────────────────────────────────

// Message represents a single chat turn.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ModelConfig holds configuration for the AI model client.
type ModelConfig struct {
	APIKey  string
	BaseURL string // overrideable for tests
	Model   string
}

// AIModel is responsible for communicating with the Claude API.
type AIModel struct {
	cfg    ModelConfig
	client *http.Client
}

// maxMessageLength is the maximum allowed length for any message content.
const maxMessageLength = 32768

// dangerousPatterns holds compiled regexps for dynamic code execution primitives.
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\beval\s*\(`),
	regexp.MustCompile(`(?i)\bexec\s*\(`),
	regexp.MustCompile(`(?i)\bexecfile\s*\(`),
	regexp.MustCompile(`(?i)\bcompile\s*\(`),
	regexp.MustCompile(`(?i)\b__import__\s*\(`),
	regexp.MustCompile(`(?i)\bos\.system\s*\(`),
	regexp.MustCompile(`(?i)\bsubprocess\b`),
	regexp.MustCompile(`(?i)\bRuntime\.exec\s*\(`),
	regexp.MustCompile(`(?i)\bnew\s+ProcessBuilder\b`),
	regexp.MustCompile(`(?i)\bFunction\s*\(`),
	regexp.MustCompile(`(?i)\bsetTimeout\s*\(`),
	regexp.MustCompile(`(?i)\bsetInterval\s*\(`),
}

// sanitizeMessage trims whitespace, rejects empty input, enforces max length,
// and returns an error if the content contains dangerous code execution primitives.
func sanitizeMessage(content string) (string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return "", fmt.Errorf("message content must not be empty")
	}
	if len(content) > maxMessageLength {
		return "", fmt.Errorf("message content exceeds maximum length of %d characters", maxMessageLength)
	}
	return content, nil
}

// validateLLMOutput checks LLM output for dangerous dynamic code execution primitives.
func validateLLMOutput(text string) error {
	for _, pat := range dangerousPatterns {
		if pat.MatchString(text) {
			return fmt.Errorf("LLM output contains disallowed dynamic code execution primitive matching pattern: %s", pat.String())
		}
	}
	return nil
}

// NewAIModel constructs an AIModel with the given config.
func NewAIModel(cfg ModelConfig) (*AIModel, error) {
	if cfg.Model == "" {
		return nil, fmt.Errorf("model must be explicitly specified; no default model is set because the previously defaulted model is not on the organization's approved list")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.approved-llm-endpoint.internal"
	}
	return &AIModel{cfg: cfg, client: &http.Client{}}, nil
}

type anthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []Message `json:"messages"`
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicResponse struct {
	Content []anthropicContent `json:"content"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete sends messages to the model and returns the assistant reply.
func (m *AIModel) Complete(ctx context.Context, messages []Message) (string, error) {
	sanitized := make([]Message, len(messages))
	for i, msg := range messages {
		clean, err := sanitizeMessage(msg.Content)
		if err != nil {
			return "", fmt.Errorf("invalid message[%d] content: %w", i, err)
		}
		sanitized[i] = Message{Role: msg.Role, Content: clean}
	}

	payload := anthropicRequest{
		Model:     m.cfg.Model,
		MaxTokens: 1024,
		Messages:  sanitized,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		m.cfg.BaseURL+"/v1/messages",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", m.cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	log.Printf("[LLM] sending request to model=%s with %d messages", m.cfg.Model, len(sanitized))

	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("[LLM] http request error: %v", err)
		return "", fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	var ar anthropicResponse
	if err := json.Unmarshal(raw, &ar); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if ar.Error != nil {
		log.Printf("[LLM] api error response: %s", ar.Error.Message)
		return "", fmt.Errorf("api error: %s", ar.Error.Message)
	}

	for _, c := range ar.Content {
		if c.Type == "text" {
			if err := validateLLMOutput(c.Text); err != nil {
				log.Printf("[LLM] output validation failed: %v", err)
				return "", fmt.Errorf("LLM output validation failed: %w", err)
			}
			log.Printf("[LLM] received text response (length=%d)", len(c.Text))
			return c.Text, nil
		}
	}
	return "", fmt.Errorf("no text content in response")
}

// ─────────────────────────────────────────────
// AI Agent — uses AIModel to accomplish tasks
// ─────────────────────────────────────────────

// AgentConfig holds agent-level settings.
type AgentConfig struct {
	SystemPrompt string
	MaxTurns     int
}

// AIAgent orchestrates multi-turn conversations using an AIModel.
type AIAgent struct {
	model   *AIModel
	cfg     AgentConfig
	history []Message
}

// NewAIAgent constructs an AIAgent backed by the given model.
func NewAIAgent(model *AIModel, cfg AgentConfig) *AIAgent {
	if cfg.MaxTurns == 0 {
		cfg.MaxTurns = 10
	}
	return &AIAgent{model: model, cfg: cfg}
}

// Chat sends a user message, appends the assistant reply, and returns it.
func (a *AIAgent) Chat(ctx context.Context, userMessage string) (string, error) {
	if len(a.history) >= a.cfg.MaxTurns*2 {
		return "", fmt.Errorf("max turns (%d) reached", a.cfg.MaxTurns)
	}

	cleanMessage, err := sanitizeMessage(userMessage)
	if err != nil {
		return "", fmt.Errorf("invalid user message: %w", err)
	}

	a.history = append(a.history, Message{Role: "user", Content: cleanMessage})

	log.Printf("[Agent] sending user message to LLM (history length=%d)", len(a.history))

	reply, err := a.model.Complete(ctx, a.history)
	if err != nil {
		// Roll back the user message so the agent remains consistent.
		a.history = a.history[:len(a.history)-1]
		log.Printf("[Agent] LLM call failed, rolled back history: %v", err)
		return "", err
	}

	if err := validateLLMOutput(reply); err != nil {
		a.history = a.history[:len(a.history)-1]
		log.Printf("[Agent] LLM reply failed output validation, rolled back history: %v", err)
		return "", fmt.Errorf("LLM reply validation failed: %w", err)
	}

	log.Printf("[Agent] received reply from LLM (length=%d)", len(reply))

	a.history = append(a.history, Message{Role: "assistant", Content: reply})
	return reply, nil
}

// Reset clears conversation history.
func (a *AIAgent) Reset() {
	a.history = nil
}

// History returns a copy of the current conversation history.
func (a *AIAgent) History() []Message {
	out := make([]Message, len(a.history))
	copy(out, a.history)
	return out
}

// ─────────────────────────────────────────────
// Helpers for tests
// ─────────────────────────────────────────────

// mockModelServer returns a *httptest.Server that replies with a fixed message.
func mockModelServer(t *testing.T, replyText string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request shape.
		var req anthropicRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(req.Messages) == 0 {
			http.Error(w, "no messages", http.StatusBadRequest)
			return
		}

		resp := anthropicResponse{
			Content: []anthropicContent{{Type: "text", Text: replyText}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// newTestAgent wires up a test server and returns an agent pointing at it.
func newTestAgent(t *testing.T, fixedReply string) (*AIAgent, *httptest.Server) {
	t.Helper()
	srv := mockModelServer(t, fixedReply)
	model, err := NewAIModel(ModelConfig{
		APIKey:  "test-key",
		BaseURL: srv.URL,
		Model:   "approved-model-v1",
	})
	if err != nil {
		t.Fatalf("NewAIModel() error = %v", err)
	}
	agent := NewAIAgent(model, AgentConfig{SystemPrompt: "You are a helpful assistant."})
	return agent, srv
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

// TestAIModel_Complete verifies that AIModel correctly sends a request and
// parses the text content from the response.
func TestAIModel_Complete(t *testing.T) {
	want := "Hello from the model!"
	srv := mockModelServer(t, want)
	defer srv.Close()

	model, err := NewAIModel(ModelConfig{APIKey: "test-key", BaseURL: srv.URL, Model: "approved-model-v1"})
	if err != nil {
		t.Fatalf("NewAIModel() error = %v", err)
	}
	got, err := model.Complete(context.Background(), []Message{
		{Role: "user", Content: "Hi"},
	})

	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if got != want {
		t.Errorf("Complete() = %q, want %q", got, want)
	}
}

// TestAIModel_Complete_APIError checks that an API-level error is surfaced.
func TestAIModel_Complete_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := anthropicResponse{Error: &struct {
			Message string `json:"message"`
		}{"invalid api key"}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	model, err := NewAIModel(ModelConfig{APIKey: "bad-key", BaseURL: srv.URL, Model: "approved-model-v1"})
	if err != nil {
		t.Fatalf("NewAIModel() error = %v", err)
	}
	_, err = model.Complete(context.Background(), []Message{{Role: "user", Content: "Hi"}})

	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid api key") {
		t.Errorf("error message %q should mention 'invalid api key'", err.Error())
	}
}

// TestAIAgent_Chat_SingleTurn verifies a basic single-turn interaction.
func TestAIAgent_Chat_SingleTurn(t *testing.T) {
	want := "The capital of France is Paris."
	agent, srv := newTestAgent(t, want)
	defer srv.Close()

	got, err := agent.Chat(context.Background(), "What is the capital of France?")
	if err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if got != want {
		t.Errorf("Chat() = %q, want %q", got, want)
	}
}

// TestAIAgent_Chat_HistoryGrows ensures history is accumulated across turns.
func TestAIAgent_Chat_HistoryGrows(t *testing.T) {
	agent, srv := newTestAgent(t, "Sure!")
	defer srv.Close()

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := agent.Chat(ctx, fmt.Sprintf("Message %d", i+1)); err != nil {
			t.Fatalf("turn %d: Chat() error = %v", i+1, err)
		}
	}

	history := agent.History()
	// 3 user messages + 3 assistant replies = 6 entries.
	if len(history) != 6 {
		t.Errorf("len(History()) = %d, want 6", len(history))
	}
	for i, msg := range history {
		wantRole := "user"
		if i%2 == 1 {
			wantRole = "assistant"
		}
		if msg.Role != wantRole {
			t.Errorf("history[%d].Role = %q, want %q", i, msg.Role, wantRole)
		}
	}
}

// TestAIAgent_Chat_MaxTurns verifies the agent refuses after MaxTurns reached.
func TestAIAgent_Chat_MaxTurns(t *testing.T) {
	agent, srv := newTestAgent(t, "ok")
	defer srv.Close()

	agent.cfg.MaxTurns = 2
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := agent.Chat(ctx, "ping"); err != nil {
			t.Fatalf("turn %d unexpected error: %v", i+1, err)
		}
	}

	_, err := agent.Chat(ctx, "one more")
	if err == nil {
		t.Fatal("expected max-turns error, got nil")
	}
	if !strings.Contains(err.Error(), "max turns") {
		t.Errorf("error %q should mention 'max turns'", err.Error())
	}
}

// TestAIAgent_Reset verifies that Reset clears conversation history.
func TestAIAgent_Reset(t *testing.T) {
	agent, srv := newTestAgent(t, "hi")
	defer srv.Close()

	if _, err := agent.Chat(context.Background(), "Hello"); err != nil {
		t.Fatalf("Chat() error = %v", err)
	}

	agent.Reset()

	if h := agent.History(); len(h) != 0 {
		t.Errorf("after Reset(), len(History()) = %d, want 0", len(h))
	}
}

// TestAIAgent_Chat_HistoryRolledBackOnError checks that a failed model call
// does not corrupt the agent's conversation history.
func TestAIAgent_Chat_HistoryRolledBackOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	model, err := NewAIModel(ModelConfig{APIKey: "test-key", BaseURL: srv.URL, Model: "approved-model-v1"})
	if err != nil {
		t.Fatalf("NewAIModel() error = %v", err)
	}
	agent := NewAIAgent(model, AgentConfig{})

	_, err = agent.Chat(context.Background(), "Will this fail?")
	if err == nil {
		t.Fatal("expected an error from the failing server")
	}

	if h := agent.History(); len(h) != 0 {
		t.Errorf("history should be empty after failed turn, got %d entries", len(h))
	}
}