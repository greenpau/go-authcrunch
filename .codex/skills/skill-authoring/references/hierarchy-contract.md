# Skill Routing Contract

Keep discoverable skills as sibling directories under `.codex/skills/`. Build the hierarchy with task-oriented routing statements, not ancestry metadata.

## Root routing in AGENTS.md

```markdown
## Repo-local skills

- Use [root-skill](.codex/skills/root-skill/SKILL.md) to perform a specific broad task.
```

Route only broad concerns from `AGENTS.md`. Route specialized work from the skill that owns the broader concern.

## Skill-to-skill routing

```markdown
## Specialized workflows

- Use [specialized-skill](../specialized-skill/SKILL.md) to perform a narrower task.
```

Every route must:

1. Start with the imperative `Use`.
2. Link the skill name to its `SKILL.md`.
3. Include `to` followed by a concrete task or trigger.
4. Be placed in the narrowest file that can make the routing decision.

A leaf skill contains no hierarchy section or placeholder. Add a routing section only when the skill actually delegates work.

Peer ownership and evidence links are supporting references. State the boundary
they document without requiring reciprocal skill loading. Informal task
delegation still needs normalization and review; excluding it from a graph
parser does not make a cyclic or ambiguous instruction conformant.

## Skill content contract

Provide the minimum project knowledge needed for implementation:

1. Responsibility and exclusions
2. Inputs and outputs
3. State model and lifecycle, when applicable
4. Behavioral rules and invariants
5. Failure and recovery behavior
6. Interactions with routed or collaborating skills
7. Language-neutral acceptance scenarios

Prefer externally meaningful behavior and clear ownership over copied code descriptions. Name a specific algorithm only when it is part of the required contract.

Diagrams are optional. A documented configuration gap is a support limit, not
permission to invent a missing public API or expand an unrelated task.

## Routing audit

For every `.codex/skills/*/SKILL.md`:

- Confirm the directory name equals the frontmatter `name`.
- Confirm frontmatter contains only `name` and `description`.
- Confirm no structural ancestry metadata or routing-only backlinks exist.
- Start at `AGENTS.md` and follow repo-local `Use [skill](path) to ...` routes.
- Confirm every route resolves to an existing `SKILL.md`.
- Confirm every repo-local skill is reachable from `AGENTS.md`.
- Reject cycles and routes whose action is too vague to select the skill reliably.
- Distinguish supporting links from hierarchy routes by requiring the `Use ... to ...` form.
- Confirm implementation-critical guidance is present in the routed skill and remains consistent with source and tests.
- Run the default `$skill-creator` validator for every changed skill.
