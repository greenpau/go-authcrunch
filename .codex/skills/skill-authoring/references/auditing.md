# Repository Skill Audits

Audit the working-tree versions of `AGENTS.md`, every direct-child skill, its UI
metadata, and its supporting resources. Inspect staged and unstaged changes
separately; an audit does not authorize staging or discarding another person's
work. Record findings and evidence in an ignored `tmp/` artifact when a full
repository review needs a durable handoff. Keep session reports out of skills.

## Routing and discovery

Inventory every `.codex/skills/*/SKILL.md`, not just files changed by the task.
Validate names, frontmatter, descriptions, and metadata against the default
skill-creator contract. Check invocation prompts name their actual skill and
describe a useful task; preserve existing invocation policies and dependencies.

Start at `AGENTS.md` and follow actionable routes, including routes in linked
references owned by a skill. Ignore fenced/inline examples when constructing the
graph. Check target files, exact skill-name labels, concrete actions, reachability,
and cycles. Read each route in context: a syntactically valid edge can still
delegate to the wrong owner.

Inspect informal `Use`, `read`, `follow`, and bare skill-name instructions too.
Do not make an audit pass by ignoring malformed delegation. Rewrite actual
delegation as `Use [skill-name](path/to/SKILL.md) to <task>`. A supporting link
states a collaborating owner's contract or supplies evidence; it does not
instruct recursive loading of a peer. Resolve reciprocal delegation through
ownership, not by disguising one edge with different wording.

Check every maintained local link and heading anchor, and make supporting files
reachable from their owning entrypoint. Distinguish repository source paths,
served URL paths, and illustrative deployment paths. Examples must not be
reported as missing source files. Do not fetch external links merely to check
local routing; verify external facts when the task changes or relies on them.

## Contracts and evidence

For each skill, identify its responsibility, inputs/outputs, meaningful state
transitions, failure/recovery behavior, cooperating owners, and acceptance
evidence. Not every workflow needs a state machine or an identical heading set.
Keep the entrypoint useful without requiring every reference to be loaded.
Move substantial mode-specific grammar, matrices, or test inventories into
task-linked references; preserve essential invariants at the entrypoint.

Trace implementation claims to current declarations, consumers, and tests.
Confirm public constructor names, package paths, serialization keys, defaults,
omission/disabled behavior, and lifecycle ownership. A test name is navigation,
not proof of the claimed scenario; inspect what the fixture actually exercises.
Test-name prefixes in `-run` expressions need matching tests, not exact symbols.

For configurable features, verify the dedicated parser, its typed result and
application boundary, grammar/defaults, external-package tests, examples, and
consumer integration. Document legacy gaps precisely in the owning skill;
do not invent constructors or describe external adapter syntax as library support.
A documentation audit does not authorize implementing unrelated missing APIs.

Compare cross-cutting claims across owners, especially identity evidence,
revocation, persistence, cookie scope, parser behavior, logging, and test scope.
Keep a rule authoritative in one place. A specialized exception must be explicit
at the broader rule, rather than silently contradicting it.

## Validation and reporting

Run the default quick validator for every changed skill; for a full audit,
validate the entire inventory. Check all local links and resources, metadata,
route reachability/cycles, retired references, and whitespace. Inspect the final
diff for dropped contracts and accidental changes outside the requested scope.

Exercise representative authoring decisions: where a new narrow skill routes,
how a moved reference remains reachable, how a peer relationship avoids a cycle,
and how an unsupported capability is reported. Diagrams are not required.
For prose-only edits, skill checks and source/test inspection are appropriate;
do not claim that runtime tests or external certification ran. New or changed
automation must be exercised, and implementation changes retain the repository's
corresponding-test and E2E requirements.

Report what was inspected, what changed, validation actually performed, and any
remaining implementation or evidence gaps. Structural checks alone establish
neither semantic completeness nor runtime correctness.
