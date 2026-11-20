// Token counts from Anthropic and OpenAI responses, plain JSON or server-sent events. Streams
// report cumulative usage, so the largest count seen is the total.

export interface TokenUsage {
  readonly inputTokens: number;
  readonly outputTokens: number;
}

const count = (value: unknown) => (typeof value === "number" && value >= 0 ? value : 0);

function usageOf(object: Record<string, unknown>): TokenUsage {
  const input =
    count(object["input_tokens"] ?? object["prompt_tokens"]) +
    count(object["cache_creation_input_tokens"]) +
    count(object["cache_read_input_tokens"]);
  return {
    inputTokens: input,
    outputTokens: count(object["output_tokens"] ?? object["completion_tokens"]),
  };
}

function* usageObjects(value: unknown, depth = 0): Generator<Record<string, unknown>> {
  if (depth > 4 || typeof value !== "object" || value === null) return;
  const record = value as Record<string, unknown>;
  const usage = record["usage"];
  if (typeof usage === "object" && usage !== null) yield usage as Record<string, unknown>;
  for (const key of ["message", "response"]) yield* usageObjects(record[key], depth + 1);
}

export class UsageCounter {
  #inputTokens = 0;
  #outputTokens = 0;
  #pending = "";
  #body = "";
  readonly #maxBody: number;

  constructor(options: { maxBufferedBody?: number } = {}) {
    this.#maxBody = options.maxBufferedBody ?? 4 * 1024 * 1024;
  }

  #observe(value: unknown) {
    for (const usage of usageObjects(value)) {
      const { inputTokens, outputTokens } = usageOf(usage);
      this.#inputTokens = Math.max(this.#inputTokens, inputTokens);
      this.#outputTokens = Math.max(this.#outputTokens, outputTokens);
    }
  }

  #observeLine(line: string) {
    if (!line.startsWith("data:")) return;
    const data = line.slice(5).trim();
    if (data.length === 0 || data === "[DONE]") return;
    try {
      this.#observe(JSON.parse(data));
    } catch {
      // A data line that is not JSON carries no usage.
    }
  }

  push(chunk: string) {
    if (this.#body.length < this.#maxBody) this.#body += chunk;
    this.#pending += chunk;
    const lines = this.#pending.split("\n");
    this.#pending = lines.pop() ?? "";
    for (const line of lines) this.#observeLine(line.trimEnd());
  }

  finish(): TokenUsage {
    this.#observeLine(this.#pending.trimEnd());
    this.#pending = "";
    if (this.#inputTokens === 0 && this.#outputTokens === 0 && this.#body.length < this.#maxBody) {
      try {
        this.#observe(JSON.parse(this.#body));
      } catch {
        // Not a JSON body: nothing more to count.
      }
    }
    this.#body = "";
    return { inputTokens: this.#inputTokens, outputTokens: this.#outputTokens };
  }
}
