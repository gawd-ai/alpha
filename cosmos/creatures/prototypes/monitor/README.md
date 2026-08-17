# monitor — injected sense-stream reader (NOT substrate)

`monitor` is the minimal pure observer for Alpha's nervous-system surface. A host subscribes its
endpoint to `Topic::PROPRIOCEPTION` and `Topic::FITNESS`; the creature renders liveness, fitness, and
budget-trajectory events as a one-line tape on stdout.

It emits no dispatches, makes no policy decision, and deliberately depends only on the public
`aether` wire rather than on `sanctum` event structs. Payload parsing is bounded by
`aether::MAX_SENSE_EVENT_BYTES`; malformed known-schema payloads render bounded placeholder fields,
and unknown schemas degrade to a generic line instead of affecting the fabric. Operators can replace
the renderer or route [`Monitor::render`](src/lib.rs) to a log or UI while keeping the same topic
subscriptions.
