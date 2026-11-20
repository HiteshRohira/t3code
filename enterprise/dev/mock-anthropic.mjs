// A stand-in for api.anthropic.com that answers Messages API calls with a canned reply and logs
// which key each request carried.
import * as NodeFS from "node:fs";
import * as NodeHttp from "node:http";

const port = Number(process.argv[2] ?? 8790);
const log = process.argv[3] ?? "mock-anthropic.log";

const sse = (event, data) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;

NodeHttp.createServer((request, response) => {
  let body = "";
  request.on("data", (chunk) => (body += chunk));
  request.on("end", () => {
    let parsed = {};
    try {
      parsed = JSON.parse(body || "{}");
    } catch {}
    NodeFS.appendFileSync(
      log,
      `${JSON.stringify({ at: new Date().toISOString(), path: request.url, key: request.headers["x-api-key"], model: parsed.model, stream: parsed.stream })}\n`,
    );
    if (request.url?.startsWith("/v1/messages/count_tokens")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ input_tokens: 10 }));
      return;
    }
    if (!request.url?.startsWith("/v1/messages")) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(
        JSON.stringify({ type: "error", error: { type: "not_found_error", message: "mock" } }),
      );
      return;
    }
    const model = parsed.model ?? "claude-haiku-4-5";
    const text =
      "Hello from the T3 Enterprise gateway. This reply came through the org's LLM gateway.";
    if (!parsed.stream) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          id: "msg_mock",
          type: "message",
          role: "assistant",
          model,
          content: [{ type: "text", text }],
          stop_reason: "end_turn",
          stop_sequence: null,
          usage: { input_tokens: 42, output_tokens: 17 },
        }),
      );
      return;
    }
    response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    response.write(
      sse("message_start", {
        type: "message_start",
        message: {
          id: "msg_mock",
          type: "message",
          role: "assistant",
          model,
          content: [],
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 42, output_tokens: 1 },
        },
      }),
    );
    response.write(
      sse("content_block_start", {
        type: "content_block_start",
        index: 0,
        content_block: { type: "text", text: "" },
      }),
    );
    response.write(
      sse("content_block_delta", {
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text },
      }),
    );
    response.write(sse("content_block_stop", { type: "content_block_stop", index: 0 }));
    response.write(
      sse("message_delta", {
        type: "message_delta",
        delta: { stop_reason: "end_turn", stop_sequence: null },
        usage: { output_tokens: 17 },
      }),
    );
    response.end(sse("message_stop", { type: "message_stop" }));
  });
}).listen(port, "127.0.0.1", () => console.log(`mock anthropic on ${port}`));
