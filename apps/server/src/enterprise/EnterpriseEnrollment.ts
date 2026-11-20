/**
 * EnterpriseEnrollment - signs the user in to the organization's IdP in a browser and exchanges
 * the one-time code for a device certificate bound to a key generated here.
 *
 * @module EnterpriseEnrollment
 */
import {
  enrollmentProofMessage,
  paths as wirePaths,
  type EnrollResponse,
} from "@t3tools/enterprise-protocol/wire";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Clock from "effect/Clock";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

import { request } from "./EnterpriseAgent.ts";
import type { EnterpriseConfigDocument } from "./EnterpriseConfig.ts";
import * as EnterpriseDevice from "./EnterpriseDevice.ts";
import * as EnterprisePolicy from "./EnterprisePolicy.ts";
import * as Transport from "./enterpriseTransport.ts";

export class EnterpriseEnrollmentError extends Schema.TaggedError<EnterpriseEnrollmentError>()(
  "EnterpriseEnrollmentError",
  { reason: Schema.String },
) {
  override get message(): string {
    return `Enrollment failed: ${this.reason}`;
  }
}

const SIGN_IN_TIMEOUT = Duration.minutes(10);

export const enroll = Effect.fn("EnterpriseEnrollment.enroll")(function* (
  config: EnterpriseConfigDocument,
  options: {
    readonly clientVersion: string;
    readonly showSignInUrl: (url: string) => Effect.Effect<void>;
  },
) {
  const serverCa = config.serverCaPem === undefined ? {} : { serverCaPem: config.serverCaPem };
  const state = Transport.randomToken();
  const callback = yield* Effect.acquireRelease(
    Effect.promise(() => Transport.awaitLoopbackCallback(state)),
    (listener) => Effect.sync(() => listener.close()),
  );
  const start = new URL(`${config.controlPlaneUrl}${wirePaths.enrollStart}`);
  start.searchParams.set("redirect_uri", callback.redirectUri);
  start.searchParams.set("state", state);
  yield* options.showSignInUrl(start.toString());

  const code = yield* Effect.promise(() => callback.code).pipe(
    Effect.timeoutOrElse({
      duration: SIGN_IN_TIMEOUT,
      orElse: () =>
        Effect.fail(
          new EnterpriseEnrollmentError({ reason: "sign-in did not finish in 10 minutes" }),
        ),
    }),
  );

  const key = Transport.generateDeviceKey();
  const reply = yield* request(`${config.controlPlaneUrl}${wirePaths.enroll}`, {
    method: "POST",
    credentials: serverCa,
    body: {
      code,
      publicKeyPem: key.publicKeyPem,
      proof: Transport.signWithDeviceKey(key.keyPem, enrollmentProofMessage(code)),
      hostname: yield* HostProcess.Hostname,
      platform: yield* HostProcess.Platform,
      clientVersion: options.clientVersion,
    },
  });
  if (reply.status !== 200) {
    const body = reply.body as { message?: unknown } | null;
    return yield* new EnterpriseEnrollmentError({
      reason:
        typeof body?.message === "string" ? body.message : `control plane answered ${reply.status}`,
    });
  }
  const enrolled = reply.body as EnrollResponse;
  const paths = yield* EnterpriseDevice.statePaths;
  const now = DateTime.formatIso(DateTime.makeUnsafe(yield* Clock.currentTimeMillis));
  const identity: EnterpriseDevice.DeviceIdentity = {
    keyPem: key.keyPem,
    certificatePem: enrolled.certificatePem,
    record: {
      deviceId: enrolled.deviceId,
      controlPlaneUrl: config.controlPlaneUrl,
      email: enrolled.user.email,
      roles: [...enrolled.user.roles],
      enrolledAt: now,
      expiresAt: enrolled.expiresAt,
    },
  };
  yield* EnterpriseDevice.writeIdentity(paths, identity);

  // Fetch the policy now so the next start enforces it instead of the bootstrap policy.
  const policy = yield* request(`${config.controlPlaneUrl}${wirePaths.policy}`, {
    credentials: { keyPem: key.keyPem, certificatePem: enrolled.certificatePem, ...serverCa },
  }).pipe(Effect.option);
  let policyVersion: number | undefined;
  if (Option.isSome(policy) && policy.value.status === 200) {
    const token = (policy.value.body as { policy?: unknown }).policy;
    if (typeof token === "string") {
      const verified = yield* EnterprisePolicy.verifyPolicyToken(config, token).pipe(Effect.option);
      if (Option.isSome(verified)) {
        yield* EnterpriseDevice.writeTextAtomically(paths.policy, `${token}\n`);
        policyVersion = verified.value.version;
      }
    }
  }
  return { identity, policyVersion };
}, Effect.scoped);
