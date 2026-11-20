/**
 * Redaction - finds credentials in a request body before it leaves the organization. Detectors
 * match fixed-prefix formats only; an entropy rule would redact every hash in a diff. Markers
 * hold no quote or backslash, so replacing inside raw JSON text keeps it valid.
 */

export interface Detector {
  readonly id: string;
  readonly description: string;
  readonly pattern: RegExp;
}

export const DETECTORS: ReadonlyArray<Detector> = [
  {
    id: "private-key",
    description: "PEM private keys",
    pattern:
      /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
  },
  {
    id: "aws-access-key",
    description: "AWS access key ids",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "aws-secret-key",
    description: "AWS secret keys assigned to a known name",
    pattern:
      /(?<=aws_secret_access_key\\?["']?\s*[:=]\s*\\?["']?)[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/gi,
  },
  {
    id: "github-token",
    description: "GitHub tokens",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{80,255})\b/g,
  },
  {
    id: "gitlab-token",
    description: "GitLab personal tokens",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  },
  { id: "slack-token", description: "Slack tokens", pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  {
    id: "stripe-key",
    description: "Stripe live keys",
    pattern: /\b[rs]k_live_[A-Za-z0-9]{24,}\b/g,
  },
  { id: "google-api-key", description: "Google API keys", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  {
    id: "anthropic-key",
    description: "Anthropic API keys",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "openai-key",
    description: "OpenAI API keys",
    pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/g,
  },
];

export interface RedactionResult {
  readonly text: string;
  /** Matches per detector id; empty when nothing was found. */
  readonly findings: Readonly<Record<string, number>>;
}

export const marker = (id: string) => `[REDACTED:${id}]`;

export function redact(text: string, detectorIds: ReadonlyArray<string>): RedactionResult {
  const findings: Record<string, number> = {};
  let output = text;
  for (const detector of DETECTORS) {
    if (!detectorIds.includes(detector.id)) continue;
    output = output.replace(detector.pattern, () => {
      findings[detector.id] = (findings[detector.id] ?? 0) + 1;
      return marker(detector.id);
    });
  }
  return { text: output, findings };
}

export const findingCount = (findings: Readonly<Record<string, number>>) =>
  Object.values(findings).reduce((total, count) => total + count, 0);
