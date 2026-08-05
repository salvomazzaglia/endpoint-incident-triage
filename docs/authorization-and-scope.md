# Authorization and scope

## Written authorization

Live collection must occur only with **explicit organizational authorization** appropriate to your jurisdiction and policies. The toolkit records:

- `authorization_reference` — ticket, memo, or case authorization ID
- `operator_label` — responder identifier (not necessarily a legal name)
- `collection_reason` — purpose of the examination
- `target_label` — host or asset identifier

The CLI refuses live collection without `--acknowledge-live-collection`.

## Case scope

Define before collection:

- Target host(s) and platform
- Collection profile (`minimal` vs `standard`)
- Time window (`--since-hours`)
- Whether command lines or event messages are required (privacy impact)
- Stop conditions if the host becomes unstable

Use `plan` to preview collectors without execution.

## Data minimization

- Default profile excludes optional sensitive fields
- Command lines and full event messages require explicit flags
- Recent-file collection limited to allowlisted roots with depth/count caps
- SSH collector records metadata only — never private key or authorized_keys content in v1.0 public fixtures

## Legal and organizational requirements

This software **does not provide legal advice**. Operators must comply with:

- Employment agreements and acceptable-use policies
- Privacy regulations applicable to their jurisdiction
- Law-enforcement or regulatory procedures when applicable
- Internal incident-response playbooks

## Stop conditions

Stop or escalate when:

- Host instability increases during collection
- Authorization is revoked or scope changes
- Mandatory collectors fail repeatedly
- You lack privilege for required artifacts and escalation is unavailable

## Evidence owner and retention

Record who owns the evidence package, where it will be stored, retention period, and secure deletion requirements under organizational policy.

## Prohibited use

Unauthorized collection, credential theft, offensive operations, and exfiltration to third-party services are prohibited. See project README and SECURITY.md.
