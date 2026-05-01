package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)
//d,jvdvfm,mfb f,m ,

type Client interface {
	Generate(ctx context.Context, prompt string) (string, error)
	Name() string
}

func NewFromEnv() Client {
	switch strings.ToLower(getenv("LLM_PROVIDER", "mock")) {
	case "openai":
		return &OpenAI{apiKey: os.Getenv("OPENAI_API_KEY"), model: getenv("OPENAI_MODEL", "gpt-4o-mini")}
	case "anthropic":
		return &Anthropic{apiKey: os.Getenv("ANTHROPIC_API_KEY"), model: getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")}
	case "gemini", "google":
		return &Gemini{apiKey: os.Getenv("GOOGLE_API_KEY"), model: getenv("GEMINI_MODEL", "gemini-1.5-flash")}
	case "openrouter":
		return &OpenRouter{apiKey: os.Getenv("OPENROUTER_API_KEY"), model: getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")}
	default:
		return &Mock{}
	}
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

type Mock struct{}
func (m *Mock) Name() string { return "mock" }
func (m *Mock) Generate(ctx context.Context, prompt string) (string, error) {
	return "[mock answer] I received MCP context and produced a response. Set LLM_PROVIDER=openai|anthropic|gemini|openrouter with an API key for real model output.", nil
}

type OpenAI struct{ apiKey, model string }
func (o *OpenAI) Name() string { return "openai/" + o.model }
func (o *OpenAI) Generate(ctx context.Context, prompt string) (string, error) {
	if o.apiKey == "" { return "", errors.New("OPENAI_API_KEY is required") }
	var res struct{ Choices []struct{ Message struct{ Content string `json:"content"` } `json:"message"` } `json:"choices"` }
	err := postJSON(ctx, "https://api.openai.com/v1/chat/completions", map[string]string{"Authorization":"Bearer "+o.apiKey}, map[string]any{
		"model": o.model,
		"messages": []map[string]string{{"role":"system","content":"You are a concise Go AI assistant."},{"role":"user","content":prompt}},
	}, &res)
	if err != nil { return "", err }
	if len(res.Choices)==0 { return "", errors.New("no OpenAI choices returned") }
	return res.Choices[0].Message.Content, nil
}

type OpenRouter struct{ apiKey, model string }
func (o *OpenRouter) Name() string { return "openrouter/" + o.model }
func (o *OpenRouter) Generate(ctx context.Context, prompt string) (string, error) {
	if o.apiKey == "" { return "", errors.New("OPENROUTER_API_KEY is required") }
	var res struct{ Choices []struct{ Message struct{ Content string `json:"content"` } `json:"message"` } `json:"choices"` }
	err := postJSON(ctx, "https://openrouter.ai/api/v1/chat/completions", map[string]string{"Authorization":"Bearer "+o.apiKey,"HTTP-Referer":"http://localhost","X-Title":"LangGraph Go MCP Demo"}, map[string]any{
		"model": o.model,
		"messages": []map[string]string{{"role":"user","content":prompt}},
	}, &res)
	if err != nil { return "", err }
	if len(res.Choices)==0 { return "", errors.New("no OpenRouter choices returned") }
	return res.Choices[0].Message.Content, nil
}

type Anthropic struct{ apiKey, model string }
func (a *Anthropic) Name() string { return "anthropic/" + a.model }
func (a *Anthropic) Generate(ctx context.Context, prompt string) (string, error) {
	if a.apiKey == "" { return "", errors.New("ANTHROPIC_API_KEY is required") }
	var res struct{ Content []struct{ Text string `json:"text"` } `json:"content"` }
	err := postJSON(ctx, "https://api.anthropic.com/v1/messages", map[string]string{"x-api-key":a.apiKey,"anthropic-version":"2023-06-01"}, map[string]any{
		"model": a.model,
		"max_tokens": 800,
		"messages": []map[string]string{{"role":"user","content":prompt}},
	}, &res)
	if err != nil { return "", err }
	if len(res.Content)==0 { return "", errors.New("no Anthropic content returned") }
	return res.Content[0].Text, nil
}

type Gemini struct{ apiKey, model string }
func (g *Gemini) Name() string { return "gemini/" + g.model }
func (g *Gemini) Generate(ctx context.Context, prompt string) (string, error) {
	if g.apiKey == "" { return "", errors.New("GOOGLE_API_KEY is required") }
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", g.model, g.apiKey)
	var res struct{ Candidates []struct{ Content struct{ Parts []struct{ Text string `json:"text"` } `json:"parts"` } `json:"content"` } `json:"candidates"` }
	err := postJSON(ctx, url, nil, map[string]any{"contents": []map[string]any{{"parts": []map[string]string{{"text": prompt}}}}}, &res)
	if err != nil { return "", err }
	if len(res.Candidates)==0 || len(res.Candidates[0].Content.Parts)==0 { return "", errors.New("no Gemini content returned") }
	return res.Candidates[0].Content.Parts[0].Text, nil
}
