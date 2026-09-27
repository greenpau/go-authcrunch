---
name: skill-authoring
description: Create or revise repo-local skills connected by actionable routing statements from AGENTS.md through broad and increasingly specialized skills. Use when documenting AuthCrunch engineering knowledge, adding or routing a skill, reorganizing the skill hierarchy, or auditing that every skill is reachable and useful to contributors.
---

# Skill Authoring

## Inherit the default authoring workflow

Use the installed `$skill-creator` skill to apply the default authoring workflow. Read it completely and apply its initialization, naming, frontmatter, progressive-disclosure, metadata, validation, and testing guidance.

Apply this skill after `$skill-creator`. Where the two differ, retain the default requirements and add the repository hierarchy and engineering-contract requirements below.

Read [AuthCrunch authoring conventions](references/authcrunch-conventions.md)
for repository-specific configuration, knowledge placement, metadata, and
validation requirements. These supplement the authoring and routing contracts
here; where they differ, this skill's contracts take precedence.

## Build a routed skill hierarchy

Store every discoverable skill as a direct child of `.codex/skills/<skill-name>/`; do not nest discoverable skill directories inside one another.

Express hierarchy as actionable routing at any depth:

```text
AGENTS.md --Use A to do X--> skill A --Use B to do Y--> skill B --> ...
```

Write each repo-local route in this form:

```markdown
Use [skill-name](relative/path/to/SKILL.md) to perform a specific task.
```

Make the action specific enough that an agent can decide whether to load the linked skill. Put routes to broad skills in `AGENTS.md`. Put routes to narrower skills in the broad skill that delegates the work. A leaf skill needs no hierarchy boilerplate.

Do not add structural ancestry sections or require a downstream skill to link back to its router. The forward `Use ... to ...` statements define the hierarchy.

Read [the skill routing contract](references/hierarchy-contract.md) when creating, moving, routing, or auditing a skill.

For a repository-wide review, read [the audit workflow](references/auditing.md).
It covers every skill and supporting resource, semantic routing, source/test
evidence, metadata, configuration gaps, and truthful validation reporting.

Treat cross-skill references that do not tell the agent to use a skill for a task as supporting links, not hierarchy routes.

## Author project engineering contracts

Capture durable behavior and workflows needed to develop, review, operate, and verify AuthCrunch. Treat the source, tests, and skills as cooperating project authorities.

Prefer observable, language-neutral contracts:

- responsibility and boundaries
- inputs, outputs, and data shapes
- state and lifecycle transitions
- ordering, concurrency, and timing behavior
- invariants and decision rules
- error, cancellation, retry, and recovery behavior
- user-visible behavior and integration boundaries
- edge cases and acceptance scenarios

Keep contracts focused on behavior and ownership instead of duplicating source listings or private-symbol inventories. Link relevant source or tests when that helps contributors navigate the current repository, but state durable rules in the skill itself.

Put shared concepts in the broadest skill that needs them. Put specialized behavior in the narrowest routed skill that owns it. Do not duplicate the same rule across routing and routed skills.

## Synchronize skills after code changes

After changing repository code, review and update the relevant repo-local skills
as part of the same implementation task. This includes library and CLI code,
UI behavior, tests, scripts, and automation. Complete this review before the
final handoff, without requiring a separate user request.

1. Map the final code and test changes to the narrowest owning skills and their
   linked references. Include collaborating owners whose documented contracts
   changed; create a routed skill only when no existing owner fits.
2. Revise affected behavior, APIs, configuration grammar/defaults, state and
   lifecycle rules, security boundaries, failure/recovery behavior, integration
   requirements, and verification guidance. Fix renamed paths and examples even
   when a refactor preserves runtime behavior. Remove superseded instructions.
3. Check the guidance against the implemented result and actual validation
   evidence. State remaining support or verification limits explicitly; keep
   transient logs and run results in ignored artifacts.
4. Validate changed skills and affected links/routes, then identify the updated
   owners in the handoff. If the existing guidance remains accurate and the code
   change adds no durable knowledge, explain that review outcome briefly instead
   of making an artificial documentation edit.

## Derive revisions from a working session

When asked to analyze a session and update skills, first inventory:

- explicit asks and requested changes;
- observed failures, logs, and reproduction commands;
- user corrections and stated operating preferences;
- implementation changes already made during the session.

Classify each item as a durable product contract, reusable troubleshooting
workflow, implementation evidence, current conformance gap, or transient
artifact. Do not preserve session IDs, timestamps, credentials, temporary
paths, one-off outputs, or implementation-library choices unless they are part
of a public compatibility contract.

Map each durable item to the narrowest existing owner. Compare its source,
tests, current contract, and documented support limits before editing. State desired
behavior and acceptance evidence in the owner; when source does not yet satisfy
the new requirement, mark that boundary partial or unavailable instead of
silently describing it as implemented. Preserve user intent as observable
behavior—for example level selection, diagnostic evidence, recovery, and
remediation—not as a transcript of the conversation.

## Optional visual aids

Diagrams are not required for this repository. Prose contracts, examples, and
acceptance scenarios are sufficient for skill conformance. Do not add diagrams,
diagram tools, or diagram-validation gates solely to complete an authoring audit.
If a requested task includes a diagram, keep its ownership and behavior consistent
with the authoritative prose and inspect its rendered output for readability.

## Workflow

1. Read `AGENTS.md`, inventory `.codex/skills/*/SKILL.md`, and follow existing `Use ... to ...` routes relevant to the task.
2. Choose the narrowest existing file that should route to the new or moved skill. Route directly from `AGENTS.md` only when no existing skill owns the concern.
3. Define the new skill's responsibility so it is cohesive, non-overlapping, and small enough to load independently.
4. Initialize the skill with the default `$skill-creator` workflow under `.codex/skills/<skill-name>/`.
5. Write the project engineering contract. Use references only for detailed material that would otherwise bloat `SKILL.md`.
6. Add a precise `Use [skill](path) to ...` statement to the selected routing file. Add no backlink solely to represent routing.
7. Add further routes inside the new skill only when it delegates narrower work.
8. Generate or refresh `agents/openai.yaml` and run the default skill validator.
9. Starting at `AGENTS.md`, audit all repo-local `Use ... to ...` routes and repair broken targets, cycles, ambiguous actions, and unreachable skills.
10. Report the new or changed routing chain using repository-relative paths.

## Route skills by task

When a task matches a routing statement, read and apply the linked skill. Continue following narrower routing statements only while they match the requested work.

Interpret routed skills as focused workflows:

- Routing skills define shared vocabulary, invariants, and dispatch decisions.
- Routed skills add narrower behavior without repeating unrelated routing context.
- A specialized skill must not silently weaken requirements already applied earlier in the route.

## Completion criteria

Finish only when:

- the default skill validator passes for every changed skill
- every repo-local skill is reachable through an actionable route from `AGENTS.md`
- every `Use ... to ...` target exists and its action is unambiguous
- no routing chain is cyclic
- no structural ancestry metadata or routing-only backlinks remain
- the authored knowledge gives contributors actionable ownership, behavior, and verification guidance
- examples and acceptance scenarios cover normal behavior and material edge cases
- implementation tasks have reconciled affected skill guidance with the final
  code and validation evidence before completion

## Acceptance scenarios

- A new narrow feature is reachable through its existing owner, with a concrete
  task route and no ancestry-only backlink; unrelated skills need not load it.
- Moving or retiring guidance preserves every durable contract at its owner,
  repairs inbound links, and leaves no unreachable supporting file.
- A peer implementation is cited for its boundary without reciprocal task
  delegation. A real routing cycle fails the audit even if all links resolve.
- A documented constructor or capability absent from source is corrected or
  marked unavailable. A passing metadata validator cannot establish support.
- A prose-only skill with applicable examples and acceptance evidence can pass
  without diagrams or diagram tooling.
- A code change that alters a configuration default updates the owning skill's
  default, example, and acceptance guidance in the same task, without another
  documentation request. A behavior-preserving rename still repairs affected
  paths; a formatting-only change can leave accurate guidance unchanged after review.
