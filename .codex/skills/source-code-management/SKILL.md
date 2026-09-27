---
name: source-code-management
description: go-authcrunch source code management and commit message rules. Use when creating, reviewing, or updating commit messages, especially when the user asks to create a commit message for a change in this repository.
---

# Source Code Management

## Change Inspection

Inspect status, staged diff, and unstaged diff separately. Never change the
index unless asked. Default a commit-message request to staged changes when the
index is nonempty and state which unstaged changes are excluded. If the index
is empty, describe the working-tree changes and say they must be staged before
committing.

## Commit Message Rules

All commits must have a proper commit message.

A hand-written commit message subject line must conform to the following
rules:

- The first line of each commit message is the subject.
- The subject line MUST be less than 87 characters long.
- The subject line MUST NOT terminate with a period (`.`).
- The subject line MUST start with a change indicator followed by a colon (`:`).

## Change Indicators

Read [change indicators](references/change-indicators.md) when selecting the
subject prefix. Use exactly one package or maintenance indicator, followed by
`: `; do not add a parenthesized scope. Prefer the owning AuthCrunch surface.
Agent skills and repository instructions use `skills`; test-only work uses
`tests`; releases use `ops: released v<VERSION>`.

## Commit Body

The commit message body must contain the following sections in this order:

1. `Before this commit:`
2. `After this commit:`
3. `Tests:`
4. `More info:`

The body may also contain the following optional sections:

1. `Resolves:`
2. `Partial Resolution:`
3. `See also:`
4. `Links:`

The following rules apply to the body of a commit message:

- Separate sections with one blank line.
- Each section title MUST end with a colon (`:`).
- Lines MUST NOT exceed 87 characters, except in `Links` and `More info`.
- Use `Resolves` ONLY when the PR or commit resolves an issue completely.
- Use `Partial Resolution` when the PR or commit addresses an issue partially.
- Use `See also` for additional related references.
- `Resolves`, `Partial Resolution`, and `See also` MUST contain valid links.
- Multiple links in those reference sections MUST be separated by comma and
  space (`, `).
- `Tests` MUST describe the command or manual check performed.
- If no smoke test was run, `Tests` MUST say `not run` and include the
  reason.
- `More info` MUST summarize the implementation details or notable decisions.

The `Links` section must contain a list of valid links or references, e.g.:

```text
  - Text reference
  - [HTTP link](http://google.com/)
```

Use this template for commit messages:

```text
indicator: concise subject under 87 characters

Before this commit: describe the previous behavior, limitation, or state.

After this commit: describe the new behavior, implementation, or state.

Tests: describe the command or manual check performed.

More info: summarize important implementation details or decisions.
```

For example, a commit message may look like this:

```text
docs: add contributing guidance

Before this commit: the repository had no guidance related to open-source
contributions.

After this commit: contribution guidance is documented in `CONTRIBUTING.md`.

Tests: reviewed the rendered Markdown manually.

More info: added a focused contributor workflow and repository etiquette notes.
```

## Commit Message File Workflow

For every request to create or generate a commit message, write it below
`tmp/commits` with a `YYYYMMDD_HHMM_` prefix and always provide the corresponding
`git commit -F ...` command. Do not require the user to ask separately for a
message file. A review-only request does not create a file unless asked.

Commit message files in `tmp/commits` are working artifacts and should not be
committed unless explicitly requested.
