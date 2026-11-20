import { describe, expect, it } from "vite-plus/test";

import { DETECTORS, redact } from "./Redaction.ts";

const all = DETECTORS.map((detector) => detector.id);
const asJson = (text: string) => JSON.stringify({ content: text });

describe("redact", () => {
  it.each([
    ["aws-access-key", "key AKIAIOSFODNN7EXAMPLE here"],
    ["aws-secret-key", 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'],
    ["github-token", `token ghp_${"a".repeat(36)}`],
    ["gitlab-token", "glpat-abcdefghij0123456789"],
    ["slack-token", "xoxb-1234567890-abcdefghij"],
    ["stripe-key", `sk_live_${"a".repeat(24)}`],
    ["google-api-key", `AIza${"b".repeat(35)}`],
    ["anthropic-key", `sk-ant-api03-${"c".repeat(40)}`],
    ["openai-key", `sk-proj-${"d".repeat(20)}T3BlbkFJ${"e".repeat(20)}`],
    ["private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----"],
  ])("finds %s inside a JSON body and keeps it valid JSON", (id, secret) => {
    const result = redact(asJson(secret), all);
    expect(result.findings).toEqual({ [id]: 1 });
    expect(JSON.parse(result.text).content).toContain(`[REDACTED:${id}]`);
  });

  it("leaves ordinary code alone", () => {
    const code = asJson(
      'const sha = "3f786850e387550fdab836ed7e6dc881de23001b"; const id = crypto.randomUUID(); // sk-test',
    );
    expect(redact(code, all)).toEqual({ text: code, findings: {} });
  });

  it("runs only the configured detectors", () => {
    const body = asJson("AKIAIOSFODNN7EXAMPLE");
    expect(redact(body, ["private-key"]).findings).toEqual({});
  });
});
