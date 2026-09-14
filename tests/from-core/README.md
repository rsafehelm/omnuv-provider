# Payloads current Core emits

Captured by serializing with **`omnuv-protocol` at its newest tag**, then
checked in here, where this agent parses them with the tag *it* pins.

That is the whole test, and the duplication is deliberate. This repository and
the protocol crate hold two views of one wire format, and the failure this
catches is precisely the two disagreeing: on 13 September a field Core writes
was renamed in a way `serde(alias)` covers in the wrong direction, and every
agent already deployed would have failed to deserialize on its next poll. A
fixture generated at test time from this repository's own dependency could not
see that, because both halves would move together.

Regenerate only when Core's output genuinely changes, and treat the diff as the
review: a key that disappears from one of these files is a key some running
agent is still looking for.
