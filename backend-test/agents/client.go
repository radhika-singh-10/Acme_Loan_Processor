package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
)

//d,jvdvfm,mfb f,m ,

type Client interface {
	Generate(ctx context.Context, prompt string) (string, error)
	Name() string
}

func NewFromEnv() Client {
	return &Mock{}
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func postJSON(ctx context.Context, url string, headers map[string]string, payload any, out any) error {
	b, err := json.Marshal(payload)
	if err != nil { return err }
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers { req.Header.Set(k, v) }
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

const maxPromptLength = 32768

var dangerousPatterns = []string{
	"eval(", "exec(", "subprocess", "os.system", "compile(", "__import__", "execfile(",
}

func sanitizePrompt(prompt string) (string, error) {
	if strings.TrimSpace(prompt) == "" {
		return "", errors.New("prompt must not be empty")
	}
	if len(prompt) > maxPromptLength {
		return "", fmt.Errorf("prompt exceeds maximum length of %d characters", maxPromptLength)
	}
	var sb strings.Builder
	for _, r := range prompt {
		if r == 0 {
			continue
		}
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String(), nil
}

func sanitizeLLMOutput(output string) error {
	lower := strings.ToLower(output)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return fmt.Errorf("LLM output contains dangerous pattern: %s", pattern)
		}
	}
	return nil
}

type Mock struct{}
func (m *Mock) Name() string { return "mock" }
func (m *Mock) Generate(ctx context.Context, prompt string) (string, error) {
	log.Printf("[Mock] Generate called with prompt: %s", prompt)
	result := "[mock answer] I received MCP context and produced a response. Set LLM_PROVIDER=mock for mock output."
	log.Printf("[Mock] Generate returning response: %s", result)
	return result, nil
}