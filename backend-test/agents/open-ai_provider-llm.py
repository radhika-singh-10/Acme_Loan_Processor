import { ChatOpenAI } from "@langchain/openai";
import { ChatAnthropic } from "@langchain/anthropic";
import { ChatGoogleGenerativeAI } from "@langchain/google-genai";
import { ChatOllama } from "@langchain/ollama";

export function createModel(provider = process.env.MODEL_PROVIDER || "openai") {
  const selected = provider.toLowerCase();

  switch (selected) {
    case "openai":
      return new ChatOpenAI({
        apiKey: process.env.OPENAI_API_KEY,
        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
        temperature: 0.2
      });

    case "anthropic":
      return new ChatAnthropic({
        apiKey: process.env.ANTHROPIC_API_KEY,
        model: process.env.ANTHROPIC_MODEL || "claude-3-5-haiku-latest",
        temperature: 0.2
      });

    case "google":
      return new ChatGoogleGenerativeAI({
        apiKey: process.env.GOOGLE_API_KEY,
        model: process.env.GOOGLE_MODEL || "gemini-1.5-flash",
        temperature: 0.2
      });

    case "ollama":
      return new ChatOllama({
        model: process.env.OLLAMA_MODEL || "llama3.1",
        temperature: 0.2
      });

    case "openrouter":
      return new ChatOpenAI({
        apiKey: process.env.OPENROUTER_API_KEY,
        model: process.env.OPENROUTER_MODEL || "openai/gpt-4o-mini",
        configuration: {
          baseURL: "https://openrouter.ai/api/v1",
          defaultHeaders: {
            "HTTP-Referer": "http://localhost",
            "X-Title": "LangChain JS MCP Demo"
          }
        },
        temperature: 0.2
      });

    default:
      throw new Error(
        `Unsupported MODEL_PROVIDER: ${provider}. Use openai, anthropic, google, ollama, or openrouter.`
      );
  }
}
 
