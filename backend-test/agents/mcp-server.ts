import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import crypto from "node:crypto";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Input sanitization helpers
// ---------------------------------------------------------------------------

/** Maximum allowed length for any string input. */
const MAX_STRING_LENGTH = 1_000;

/**   djbvdjvb
 * Sanitize a string input:
 *  - Enforce maximum length
 *  - Strip ASCII control characters (except ordinary whitespace)
 *  - Remove common injection patterns (script tags, null bytes, etc.)
 */
function sanitizeString(value: string): string {
  if (value.length > MAX_STRING_LENGTH) {
    throw new Error(
      `Input exceeds maximum allowed length of ${MAX_STRING_LENGTH} characters.`
    );
  }

  // Remove null bytes
  let sanitized = value.replace(/\0/g, "");

  // Strip ASCII control characters (0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F)
  // while preserving tab (0x09), newline (0x0A), and carriage return (0x0D).
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Remove HTML/script injection patterns
  sanitized = sanitized.replace(/<script[\s\S]*?<\/script>/gi, "");
  sanitized = sanitized.replace(/<[^>]*>/g, "");

  // Remove potential template/command injection sequences
  sanitized = sanitized.replace(/`[^`]*`/g, "");
  sanitized = sanitized.replace(/\$\{[^}]*\}/g, "");

  return sanitized;
}

/**
 * Validate a numeric input:
 *  - Must be a finite number
 *  - Must be within the safe integer range
 */
function sanitizeNumber(value: number): number {
  if (!Number.isFinite(value)) {
    throw new Error("Numeric input must be a finite number.");
  }
  if (value > Number.MAX_SAFE_INTEGER || value < Number.MIN_SAFE_INTEGER) {
    throw new Error(
      `Numeric input is outside the safe integer range (${Number.MIN_SAFE_INTEGER} to ${Number.MAX_SAFE_INTEGER}).`
    );
  }
  return value;
}

// ---------------------------------------------------------------------------

const APPROVED_SERVER_NAME = "org-approved-mcp-server";

const server = new McpServer({
  name: APPROVED_SERVER_NAME,
  version: "0.1.0",
});

server.registerTool(
  "echo",
  {
    title: "Echo",
    description: "Echo back the provided message.",
    inputSchema: {
      message: z.string().describe("The message to echo back"),
    },
  },
  async ({ message }) => {
    const safeMessage = sanitizeString(message);
    return {
      content: [{ type: "text", text: safeMessage }],
    };
  }
);

server.registerTool(
  "add",
  {
    title: "Add",
    description: "Add two numbers and return their sum.",
    inputSchema: {
      a: z.number().describe("First addend"),
      b: z.number().describe("Second addend"),
    },
  },
  async ({ a, b }) => {
    const safeA = sanitizeNumber(a);
    const safeB = sanitizeNumber(b);
    return {
      content: [{ type: "text", text: String(safeA + safeB) }],
    };
  }
);

server.registerTool(
  "now",
  {
    title: "Current time",
    description: "Return the current server time as an ISO-8601 string.",
    inputSchema: {},
  },
  async () => ({
    content: [{ type: "text", text: new Date().toISOString() }],
  })
);

server.registerResource(
  "greeting",
  "greeting://hello",
  {
    title: "Greeting",
    description: "A simple static greeting resource.",
    mimeType: "text/plain",
  },
  async (uri) => ({
    contents: [
      {
        uri: uri.href,
        text: `Hello from ${APPROVED_SERVER_NAME}!`,
      },
    ],
  })
);

/**
 * Generate an HMAC-based server identity token derived from MCP_AUTH_TOKEN
 * and a fixed label. This token is written to stderr so the MCP client can
 * authenticate the server before trusting it.
 */
function generateServerIdentityToken(authToken: string): string {
  const SERVER_IDENTITY_LABEL = "mcp-server-identity-v1";
  return crypto
    .createHmac("sha256", authToken)
    .update(SERVER_IDENTITY_LABEL)
    .digest("hex");
}

function authenticateClient(): void {
  const expectedToken = process.env.MCP_AUTH_TOKEN;
  if (!expectedToken || expectedToken.trim() === "") {
    console.error(
      `[${APPROVED_SERVER_NAME}] FATAL: MCP_AUTH_TOKEN environment variable is not set. ` +
        "The server requires a shared secret to authenticate clients."
    );
    process.exit(1);
  }

  const clientToken = process.env.CLIENT_AUTH_TOKEN;
  if (!clientToken || clientToken.trim() === "") {
    console.error(
      `[${APPROVED_SERVER_NAME}] FATAL: Client did not supply CLIENT_AUTH_TOKEN. ` +
        "Authentication failed."
    );
    process.exit(1);
  }

  // Constant-time comparison to prevent timing attacks.
  const expected = Buffer.from(expectedToken, "utf8");
  const provided = Buffer.from(clientToken, "utf8");
  if (
    expected.length !== provided.length ||
    !crypto.timingSafeEqual(expected, provided)
  ) {
    console.error(
      `[${APPROVED_SERVER_NAME}] FATAL: CLIENT_AUTH_TOKEN does not match. ` +
        "Authentication failed."
    );
    process.exit(1);
  }

  console.error(`[${APPROVED_SERVER_NAME}] client authenticated successfully.`);
}

async function main() {
  // Authenticate the client before accepting any requests.
  authenticateClient();

  const authToken = process.env.MCP_AUTH_TOKEN as string;

  // Generate and emit the server identity token so the MCP client can
  // authenticate the server out-of-band before trusting it.
  const serverIdentityToken = generateServerIdentityToken(authToken);
  console.error(
    `[${APPROVED_SERVER_NAME}] SERVER_IDENTITY_TOKEN=${serverIdentityToken}`
  );

  // If a path is provided via SERVER_IDENTITY_TOKEN env var, the client can
  // read and verify the token from that path out-of-band.
  if (process.env.SERVER_IDENTITY_TOKEN_PATH) {
    const fs = await import("node:fs/promises");
    await fs.writeFile(
      process.env.SERVER_IDENTITY_TOKEN_PATH,
      serverIdentityToken,
      { encoding: "utf8" }
    );
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Note: don't write to stdout; it's used for the JSON-RPC transport.
  console.error(`[${APPROVED_SERVER_NAME}] listening on stdio`);
}

main().catch((err) => {
  console.error(`[${APPROVED_SERVER_NAME}] fatal error:`, err);
  process.exit(1);
});