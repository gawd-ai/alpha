# scorers — injected `FitnessScorer` models (NOT substrate)

Reference fitness criteria for [`creatures/fitness-selector`](../../../creatures/fitness-selector).
The selector aggregates the kernel's proprioceptive fitness signal per creature and asks an
**injected** `FitnessScorer` to turn it into a score; the substrate ships **no** criterion of its own
(T4). These are the minimal references — operators write their own (windowed averages, latency
tradeoffs, peer-comparative percentiles).

| Crate | Scores by |
|---|---|
| `scorer-success-rate` | useful-handles / total-handles (the bare-minimum reference) |
| `scorer-latency` | lower mean handle-latency scores higher, linear against a configured ceiling |
| `scorer-roundrobin` | every creature that has handled anything scores 1.0 (alive = fit; never production) |
