import { tokenizeCliArgs } from "@t3tools/shared/cliArgs";

const T3CODE_CODEX_LAUNCH_ARGS_ENV = "T3CODE_CODEX_LAUNCH_ARGS";
const T3E_CODEX_GATEWAY_URL_ENV = "T3E_CODEX_GATEWAY_URL";

/**
 * Codex ignores OPENAI_BASE_URL, so an enterprise gateway becomes its own model provider. Only a
 * loopback URL is accepted: managed policy strips launch-argument overrides, and this variable
 * must not reopen that door. Values carry no quotes because T3 tokenizes these arguments.
 */
const codexGatewayArgs = (gatewayUrl: string | undefined): string => {
  if (gatewayUrl === undefined || /\s/.test(gatewayUrl.trim())) return "";
  let url: URL;
  try {
    url = new URL(gatewayUrl.trim());
  } catch {
    return "";
  }
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1") return "";
  return [
    "-c model_provider=t3-enterprise",
    "-c model_providers.t3-enterprise.name=t3-enterprise",
    `-c model_providers.t3-enterprise.base_url=${url.href.replace(/\/$/, "")}`,
    "-c model_providers.t3-enterprise.env_key=OPENAI_API_KEY",
    "-c model_providers.t3-enterprise.wire_api=responses",
  ].join(" ");
};

/** Sessions recorded before enrollment keep their provider on resume unless told otherwise. */
export const codexGatewayModelProvider = (environment: NodeJS.ProcessEnv) =>
  codexGatewayArgs(environment[T3E_CODEX_GATEWAY_URL_ENV]) === "" ? undefined : "t3-enterprise";

export const resolveCodexLaunchArgs = (
  launchArgs?: string,
  environment: NodeJS.ProcessEnv = process.env,
) =>
  [
    codexGatewayArgs(environment[T3E_CODEX_GATEWAY_URL_ENV]),
    environment[T3CODE_CODEX_LAUNCH_ARGS_ENV]?.trim() || launchArgs?.trim() || "",
  ]
    .join(" ")
    .trim();

const codexLaunchArgv = (launchArgs?: string): ReadonlyArray<string> => tokenizeCliArgs(launchArgs);

export const codexAppServerArgs = (launchArgs?: string) => [
  "app-server",
  ...codexLaunchArgv(launchArgs),
];

export const codexExecLaunchArgs = (launchArgs?: string) => {
  const args = codexLaunchArgv(launchArgs);
  const execArgs: Array<string> = [];

  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === undefined) continue;

    if (arg === "--strict-config" || arg.startsWith("--config=") || arg.startsWith("-c=")) {
      execArgs.push(arg);
    } else if (arg === "--config" || arg === "-c" || arg === "--enable" || arg === "--disable") {
      const value = args[index + 1];
      if (value !== undefined && !value.startsWith("-")) {
        execArgs.push(arg, value);
        index++;
      }
    } else if (arg.startsWith("--enable=") || arg.startsWith("--disable=")) {
      execArgs.push(arg);
    }
  }

  return execArgs;
};
