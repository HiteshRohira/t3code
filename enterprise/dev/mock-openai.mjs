// A stand-in for api.openai.com that answers Responses API calls with a canned streamed reply and
// logs which key each request carried.
import * as NodeFS from "node:fs";
import * as NodeHttp from "node:http";

const port = Number(process.argv[2] ?? 8792);
const log = process.argv[3] ?? "mock-openai.log";

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
      `${JSON.stringify({ at: new Date().toISOString(), path: request.url, key: request.headers.authorization, model: parsed.model })}\n`,
    );
    if (!request.url?.startsWith("/v1/responses")) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { message: "only /v1/responses is mocked" } }));
      return;
    }
    response.writeHead(200, { "content-type": "text/event-stream" });
    const send = (event) =>
      response.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
    const text = "Hello from the organization's gateway (mock OpenAI).";
    const item = { type: "message", id: "msg_1", role: "assistant", content: [] };
    send({ type: "response.created", response: { id: "resp_1" } });
    send({ type: "response.output_item.added", output_index: 0, item });
    send({
      type: "response.output_text.delta",
      item_id: "msg_1",
      output_index: 0,
      content_index: 0,
      delta: text,
    });
    send({
      type: "response.output_item.done",
      output_index: 0,
      item: { ...item, content: [{ type: "output_text", text }] },
    });
    send({
      type: "response.completed",
      response: {
        id: "resp_1",
        usage: { input_tokens: 120, output_tokens: 14, total_tokens: 134 },
      },
    });
    response.end();
  });
}).listen(port, "127.0.0.1");
