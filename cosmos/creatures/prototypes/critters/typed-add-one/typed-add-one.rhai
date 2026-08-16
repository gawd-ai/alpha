// A typed Function implemented by the cheapest creature tier.
//
// The executor sends gawd.function.call.v1 JSON through the ordinary one-envelope creature ABI.
// This critter copies the dynamic AttemptId into its FunctionResultV1; it never invents identity or
// authority locally.
fn handle(env) {
    if env.schema != "gawd.function.call.v1" || env.text_truncated {
        return ();
    }
    if !function_call_verify(env.text, env.from, env.to) {
        return ();
    }

    let message = json_parse(env.text);
    if message.operation != "call" {
        return ();
    }
    // `call` is a Rhai keyword, so use map indexing for the wire field.
    let invocation = message["call"];
    if invocation.function.entrypoint != "add_one" || invocation.input.kind != "inline" {
        return ();
    }

    json_stringify(#{
        operation: "result",
        result: #{
            attempt: invocation.attempt,
            outcome: #{
                Ok: #{
                    kind: "inline",
                    value: #{ answer: invocation.input.value.value + 1 }
                }
            }
        }
    })
}
