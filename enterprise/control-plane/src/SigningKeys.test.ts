import * as NodeServices from "@effect/platform-node/NodeServices";
import { assert, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";

import * as SigningKeys from "./SigningKeys.ts";

it.layer(NodeServices.layer)("SigningKeys", (it) => {
  it.effect("stages a rotated key: published at once, signing only after activation", () =>
    Effect.gen(function* () {
      const dir = yield* (yield* FileSystem.FileSystem).makeTempDirectoryScoped();
      const first = yield* SigningKeys.loadOrCreate(dir);
      const staged = yield* SigningKeys.rotate(dir);

      const published = yield* SigningKeys.loadOrCreate(dir);
      assert.strictEqual(published.active.kid, first.active.kid);
      assert.deepStrictEqual(
        published.all.map((key) => key.kid),
        [staged.kid, first.active.kid],
      );

      yield* SigningKeys.activate(dir);
      const activated = yield* SigningKeys.loadOrCreate(dir);
      assert.strictEqual(activated.active.kid, staged.kid);
      assert.include(
        activated.all.map((key) => key.kid),
        first.active.kid,
      );
      const again = yield* Effect.flip(SigningKeys.activate(dir));
      assert.include(again.message, "no staged key");
    }).pipe(Effect.scoped),
  );
});
