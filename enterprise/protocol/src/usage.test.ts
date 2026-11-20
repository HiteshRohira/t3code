import { describe, expect, it } from "vite-plus/test";

import { UsageCounter } from "./usage.ts";

const count = (chunks: ReadonlyArray<string>) => {
  const counter = new UsageCounter();
  for (const chunk of chunks) counter.push(chunk);
  return counter.finish();
};

describe("UsageCounter", () => {
  it("reads an Anthropic JSON response, including cache tokens", () => {
    expect(
      count([
        JSON.stringify({
          usage: { input_tokens: 10, cache_read_input_tokens: 5, output_tokens: 3 },
        }),
      ]),
    ).toEqual({ inputTokens: 15, outputTokens: 3 });
  });

  it("reads an Anthropic stream split across chunks", () => {
    const stream = [
      'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":42,"output_tokens":1}}}\n\n',
      'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":17}}\n\n',
    ].join("");
    expect(count([stream.slice(0, 37), stream.slice(37, 120), stream.slice(120)])).toEqual({
      inputTokens: 42,
      outputTokens: 17,
    });
  });

  it("reads OpenAI chat and Responses usage", () => {
    expect(count([JSON.stringify({ usage: { prompt_tokens: 8, completion_tokens: 2 } })])).toEqual({
      inputTokens: 8,
      outputTokens: 2,
    });
    expect(
      count([
        'data: {"type":"response.completed","response":{"usage":{"input_tokens":30,"output_tokens":9}}}\n',
        "data: [DONE]\n",
      ]),
    ).toEqual({ inputTokens: 30, outputTokens: 9 });
  });

  it("counts nothing in a body without usage", () => {
    expect(count(["not json"])).toEqual({ inputTokens: 0, outputTokens: 0 });
  });
});
