# plugin runtime

internal effect service for t3 product plugins.

it uses a deterministic, stack-safe reconciliation planner and one effect child scope per active plugin. `PluginRuntime` is provided through `layer()`, so the composing effect scope owns shutdown. updates stage changed plugins and their dependents, publish contributions atomically, and roll back without replacing the live composition when activation fails.

cordis is not a dependency. a pure-only executor was rejected because plugin lifetimes and async cleanup should be owned by effect scopes.

## contributions

plugins register detached, deeply frozen, json-compatible declarative metadata and an optional host-only live value. snapshots and `contributions(slot)` expose only frozen metadata. executable values never cross the rpc boundary.

`contributions(slot)` returns the committed generation with its entries. hosts must pass that generation to `useContribution(...)`; stale callers fail instead of invoking a handler from a different composition. invocation, reconciliation, and shutdown share the same transition authority, so a plugin scope cannot retire while its contribution is running.

contribution ids are unique within each slot across the active composition. duplicate ids fail candidate validation and leave the previous generation live.

## limits

reentrancy is detected through the async context of plugin callbacks. code a plugin starts itself (promises, fresh effect runtimes, contribution fibers) is rejected with `PluginRuntimeReentrancyError`. a host-owned fiber that plugin code resumes keeps the host's context, so its runtime calls wait for the current transition like any host caller. if the plugin callback then awaits that call, the transition never finishes. plugins only receive their activation context, so this needs host code that hands fibers to plugins; hosts must not do that.
