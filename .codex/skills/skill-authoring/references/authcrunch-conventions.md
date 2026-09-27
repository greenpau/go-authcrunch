# AuthCrunch Authoring Conventions

Apply these repository-specific conventions alongside the authoring and routing
contracts in `SKILL.md`. They supplement those contracts without weakening them.

## Configuration and implementation ownership

[coding-directives](../../coding-directives/SKILL.md) owns implementation rules;
[testing-and-ci](../../testing-and-ci/SKILL.md) owns code-test requirements.
Skill-only validation is owned by this authoring skill. If the requested work
also changes code or automation, the corresponding root routes apply.
Generic skills contain reusable repository rules; implementation
skills contain verified package paths, contracts, lifecycle invariants, and
validation commands. Split a concern only when distinct behavior justifies it.

For a configurable feature, identify its public config type, dedicated `parser`
package, exported directive constructor, grammar/defaults, application API, and
unit/example/E2E coverage in the owning skill. Follow the shared
[configuration parser shape](../../coding-directives/references/configuration-parsers.md)
for architecture; keep only the feature's concrete binding and contracts in
its skill. Typed fields or an external handler alone are not parser support.

## Knowledge placement and retirement

Keep public API and security-contract reasoning beside Go declarations. Keep
implementation rationale, local operations, and validation procedures in the
narrow owning skill. Keep `AGENTS.md` to routing and repository-wide invariants
and `README.md` to human onboarding and common commands. This repository has
no `docs/` directory. Put configuration, client integration, operational, and
validation guidance in the owning skill or its linked references.

Follow the [repository scope](../../coding-directives/SKILL.md#repository-scope)
rule for Caddy agent handoff placement. Preserve reusable library contracts in
skills when moving consumer-specific handoff notes to `tmp/`.

Before retiring standalone guidance, audit every inbound reference and assign
each durable statement to its authoritative declaration or owning skill.
Remove obsolete prose and links only after that transfer. Route to the owner
instead of mirroring a rule into multiple skills.

## Metadata and validation

Keep frontmatter to `name` and a description that identifies concrete triggers.
Use lowercase hyphen-case folder names under 64 characters. Keep
`agents/openai.yaml` interface values quoted: `display_name`,
`short_description`, and a `default_prompt` naming the exact `$skill-name`.
Preserve existing invocation policy and dependencies when editing metadata.

Keep routers short and leaf skills focused. Do not add TODO/TBD content,
creation history, empty resources, README files, or rules Codex already knows.
Update `AGENTS.md` and parent routing when discoverability changes. Validate
every changed skill with the default skill-creator quick validator and inspect
all concrete references. Run added automation; for release behavior, use an
isolated fixture repository and local bare remote.
