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

**When to recapture: when Core moves to a newer protocol tag than this agent
pins.** That is the only time the two views differ, so it is the only time this
test checks the gap it exists for. With equal pins (v0.21.0 on both, 24
September 2026), it checks that the 14 September capture still parses. That is
useful, and it is a different claim.

Regenerate only when Core's output genuinely changes, and treat the diff as the
review: a key that disappears from one of these files is a key some running
agent is still looking for.

## The goldens of both Cores (omnuv's modular design, A7)

Three directories, each a byte copy of where its files are generated, read
by `src/agent_goldens.rs` through the functions the agent itself reads with:

```text
fakecore/        omnuv tests/fakecore/golden/ at c16cf589: Core-to-agent
                 files only, written by the v0.27.0 serializer
protocol-v0.27/  omnuv-protocol tests/golden/v0.27/ at tag v0.28.0: what a
                 v0.27 Core sends, and the v0.27 handshake and heartbeat
protocol-v0.28/  omnuv-protocol tests/golden/v0.28/ at tag v0.28.0: the same
                 with every v0.28.0 field, and names.json
```

Copied, never edited, so a diff against the source is the review:

```bash
for f in tests/from-core/protocol-v0.28/*.json; do
  git -C ../omnuv-protocol show v0.28.0:tests/golden/v0.28/"$(basename "$f")" | cmp - "$f"
done
```

The fakecore's `onvt-…` strings (`onvt-setup-key`,
`onvt-certificate-bootstrap`) are its fixture words, not credentials; its
README says so. Recopy when omnuv's fake Core is regenerated from v0.28.0
types (its W12), and when a protocol tag adds a golden.
