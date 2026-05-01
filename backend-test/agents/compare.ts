import "dotenv/config";
import { ChatPromptTemplate } from "@langchain/core/prompts";
import { StringOutputParser } from "@langchain/core/output_parsers";
import { createModel, type Provider } from "./models.js";
import { appendFileSync } from "fs";

function logLLMInteraction(provider: string, input: string, output: string, error?: string): void {
  const entry = {
    timestamp: new Date().toISOString(),
    provider,
    input,
    output: output || null,
    error: error || null,
  };
  appendFileSync("llm_interactions.log", JSON.stringify(entry) + "\n", "utf8");
}

function validateAndSanitizeLLMOutput(output: string): string {
  const DANGEROUS_PATTERNS: RegExp[] = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*['"`]/gi,
    /\bsetInterval\s*\(\s*['"`]/gi,
    /\bexecSync\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bexecFile\s*\(/gi,
    /\brequire\s*\(\s*['"`]child_process/gi,
    /\bimport\s*\(\s*['"`]child_process/gi,
    /\bvm\.runInNewContext\s*\(/gi,
    /\bvm\.runInThisContext\s*\(/gi,
    /\bvm\.Script\s*\(/gi,
    /\bProcessBuilder\s*\(/gi,
    /\bRuntime\.getRuntime\s*\(\s*\)\.exec\s*\(/gi,
  ];

  const detectedPatterns: string[] = [];

  for (const pattern of DANGEROUS_PATTERNS) {
    const matches = output.match(pattern);
    if (matches) {
      detectedPatterns.push(...matches.map((m) => m.trim()));
    }
  }

  if (detectedPatterns.length > 0) {
    const unique = [...new Set(detectedPatterns)];
    console.warn(
      `[SECURITY WARNING] LLM output contained dangerous code execution primitives and was suppressed. Detected: ${unique.join(", ")}`
    );
    return "[OUTPUT SUPPRESSED: Response contained potentially dangerous code execution primitives.]";
  }

  return output;
}

// TODO: Populate this list with providers from the organization's approved LLM registry only.
const providers: Provider[] = ["openai","cohere","google","ibm","anthropic","deepseek","microsoft","mistral","bedrock","ollama","groq","together","openrouter"];

const rawInput = process.argv.slice(2).join(" ");

const sanitized = rawInput
  .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
  .replace(/\s+/g, " ")
  .trim()
  .slice(0, 2000);

const DEFAULT_PROMPT = "Give one test scenario for an AI governance policy engine.";
if (rawInput.length > 0 && sanitized.length === 0) {
  console.error("Error: Input contained only invalid characters and was rejected.");
  process.exit(1);
}
const promptText = sanitized || DEFAULT_PROMPT;

const prompt = ChatPromptTemplate.fromMessages([
  ["system", "You are a QA engineer. Answer in 2-3 concise bullets."],
  ["human", "{input}"],
]);

for (const provider of providers) {
  try {
    const chain = prompt.pipe(createModel(provider)).pipe(new StringOutputParser());
    const rawResult = await chain.invoke({ input: promptText });
    const result = validateAndSanitizeLLMOutput(rawResult);
    logLLMInteraction(provider, promptText, result);
    console.log(`\n================ ${provider.toUpperCase()} ================`);
    console.log(result);
  } catch (error) {
    logLLMInteraction(provider, promptText, "", (error as Error).message);
    console.log(`\n================ ${provider.toUpperCase()} ================`);
    console.log(`Skipped: ${(error as Error).message}`);
  }
}
