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

function redactPII(input: string): string {
  let redacted = input;

  // Redact email addresses
  redacted = redacted.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  // Redact SSNs (e.g. 123-45-6789 or 123456789)
  redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]");
  redacted = redacted.replace(/\b\d{9}\b/g, "[REDACTED_SSN]");

  // Redact phone numbers (various formats)
  redacted = redacted.replace(/(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b/g, "[REDACTED_PHONE]");

  // Redact credit card numbers (13-16 digit sequences, optionally separated by spaces or dashes)
  redacted = redacted.replace(/\b(?:\d[ \-]?){13,16}\b/g, "[REDACTED_CREDIT_CARD]");

  // Redact IP addresses
  redacted = redacted.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "[REDACTED_IP]");

  // Redact dates of birth (common formats: MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD)
  redacted = redacted.replace(/\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g, "[REDACTED_DOB]");
  redacted = redacted.replace(/\b\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}\b/g, "[REDACTED_DOB]");

  // Redact home addresses (basic pattern: number followed by street name and type)
  redacted = redacted.replace(/\b\d+\s+[A-Za-z0-9\s,\.]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?/gi, "[REDACTED_ADDRESS]");

  return redacted;
}

// TODO: No providers are currently approved. This list must remain empty until providers are identified and registered from the organization's approved LLM registry.
const providers: Provider[] = [];

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
const promptText = redactPII(sanitized || DEFAULT_PROMPT);

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