---
name: skill-authoring-patterns
description: Create, rewrite, review, or validate go-authcrunch repo-local skills, agents/openai.yaml metadata, AGENTS.md routing, and focused implementation or workflow skills.
---

# Skill Authoring Patterns

Use this skill with the default `$skill-creator`; read that skill completely
first. Pair with `$coding-directives` for repository edits and
`$testing-and-ci` for validation.

Default repo-local skills to `.codex/skills`. Keep frontmatter to `name` and a
trigger-rich `description`. Use lowercase hyphen-case folder names under 64
characters. Keep `agents/openai.yaml` to quoted `display_name`,
`short_description`, and a `default_prompt` that names the exact `$skill-name`.
Preserve existing invocation policy and dependencies when editing metadata.

Route from `AGENTS.md` and broad concern skills to narrow implementation
owners. Generic skills contain reusable repository rules; implementation
skills contain verified package paths, contracts, lifecycle invariants, and
validation commands. Split a concern only when distinct behavior justifies it.
Keep this graph one-way rather than making leaf skills reload their routers.

Keep public API and security-contract reasoning beside Go declarations. Keep
implementation rationale, local operations, and validation procedures in the
narrow owning skill. Keep `AGENTS.md` to routing and repository-wide invariants
and `README.md` to human onboarding and common commands. This repository has
no `docs/` directory. Put configuration, client integration, operational, and
validation guidance in the owning skill or its linked references.

Before retiring standalone guidance, audit every inbound reference and assign
each durable statement to its authoritative declaration or owning skill.
Remove obsolete prose and links only after that transfer. Do not mirror the
same rule into multiple skills; route to the owner instead.

Keep routers short and leaf skills focused. Do not add TODO/TBD content,
creation history, empty resources, README files, or rules Codex already knows.
Update `AGENTS.md` and parent routing when discoverability changes. Validate
every changed skill with the default skill-creator quick validator and inspect
all concrete references. Run added automation; for release behavior, use an
isolated fixture repository and local bare remote.
