package example;

import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import tools.jackson.databind.json.JsonMapper;
//vlkjdvbkjvbk
/** Minimal MCP server: stdio transport and a single {@code echo} tool. */
public final class BasicMcpServer {

    public static void main(String[] args) {
        var jsonMapper = new JacksonMcpJsonMapper(JsonMapper.builder().build());
        var transport = new StdioServerTransportProvider(jsonMapper);

        McpSchema.JsonSchema echoSchema = new McpSchema.JsonSchema(
                "object",
                Map.of("text", Map.of("type", "string", "description", "Text to echo back")),
                List.of("text"),
                false,
                null,
                null);

        McpSyncServer server = McpServer.sync(transport)
                .serverInfo("basic-mcp-server", "1.0.0")
                .toolCall(
                        Tool.builder()
                                .name("echo")
                                .description("Echoes the given text back to the client.")
                                .inputSchema(echoSchema)
                                .build(),
                        (exchange, request) -> {
                            Object text = request.arguments().get("text");
                            return CallToolResult.builder()
                                    .content(List.of(new McpSchema.TextContent(String.valueOf(text))))
                                    .build();
                        })
                .build();

        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            server.close();
        }
    }

    private BasicMcpServer() {}
}
