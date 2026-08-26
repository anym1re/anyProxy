## Changes

-

## Why

## Verification

## Breaking changes

<!--
Keep the section below only when the change touches the front door, the
FakeTLS parser, the panel-agent protocol, the agent channel or its cache,
crypto and credential handling, authentication, the audit log, or migrations.
Remove it otherwise.
-->

## Security review

- [ ] Threats for the touched component reviewed
- [ ] No secret reaches a log, an error message, a static file or a default API response
- [ ] Secret comparison stays constant-time
- [ ] Failure path stays indistinguishable from a normal visitor
- [ ] External surface unchanged
- [ ] Schema change carries no client address column
- [ ] New parser has a fuzz target
