# fixtures — native boundary specimens (TEST ONLY)

These crates are deliberately reduced native creatures used by the Sanctum integration and
memory-safety suites. They are not operator models and are never production recommendations:

| Fixture | What it proves |
|---|---|
| `echo-daemon`, `echo-daemon-v2` | the native walking skeleton, replacement, and reload freshness |
| `loopback-gateway` | local/remote gateway routing symmetry |
| `panic-daemon` | a panicking handler is isolated at the creature boundary |
| `runaway-thread-daemon` | an unmanaged thread forces safe resource retention instead of unsafe `dlclose` |
| `welbehaved-thread-daemon` | a managed worker joins before native unload |

Use a production organ from [`../../`](../../) or an injected strategy from [`../`](../) when
building real behavior. A new fixture belongs here only when it isolates a boundary or fault that a
normal prototype should not embody.
