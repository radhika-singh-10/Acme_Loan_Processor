import "dotenv/config";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const mode = process.argv[2] || "stdio";

async function connectToLocalPublicMcpServer() {
  // Uses the public open-source MCP reference server from npm.
  // This is useful when you do not have a remote public MCP URL.
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["-y", "@modelcontextprotocol/server-everything"]
  });  //,DocumentFragment,df

  return connectAndListTools(transport, "public npm MCP server: @modelcontextprotocol/server-everything");
}

async function connectToRemotePublicMcpServer() {
  if (!process.env.PUBLIC_MCP_URL) {
    throw new Error("PUBLIC_MCP_URL is missing in .env");
  }

  const transport = new StreamableHTTPClientTransport(new URL(process.env.PUBLIC_MCP_URL));
  return connectAndListTools(transport, process.env.PUBLIC_MCP_URL);
}

async function connectAndListTools(transport, label) {
  const client = new Client({ name: "langchain-js-mcp-demo", version: "1.0.0" });
  await client.connect(transport);

  console.log(`\nConnected to MCP server: ${label}\n`);

  const tools = await client.listTools();
  console.log("Available tools:");
  for (const tool of tools.tools || []) {
    console.log(`- ${tool.name}: ${tool.description || "No description"}`);
  }

  await client.close();
}

try {
  if (mode === "http") {
    await connectToRemotePublicMcpServer();
  } else {
    await connectToLocalPublicMcpServer();
  }
} catch (error) {
  console.error("\nError running MCP demo:");
  console.error(error.message);
  process.exit(1);
}
