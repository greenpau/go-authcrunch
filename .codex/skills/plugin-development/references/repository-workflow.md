# Plugin Repositories and Shared Guidance

Read this guide when starting a separate backend plugin repository, writing its
`AGENTS.md`, or layering a companion host plugin on the AuthCrunch contract.
Use the [development blueprint](development-blueprint.md) for implementation and
the [category catalog](plugin-categories.md) for the actual consumer boundary.

Contents: [ownership](#repository-ownership), [loading guidance](#load-guidance-from-another-repository),
[bootstrap](#bootstrap-a-backend-repository), [backend AGENTS.md](#backend-agentsmd-template),
[companions](#companion-host-plugins), [companion AGENTS.md](#companion-agentsmd-template),
and [acceptance](#acceptance).

## Repository ownership

| Repository | Owns | Guidance it maintains or consumes |
| --- | --- | --- |
| `go-authcrunch` | Core domain APIs, category contracts, and reference plugins under `plugins/<category>/<name>` | Shared plugin-development skills and synthetic reference acceptance requirements |
| Separate backend plugin, such as `go-authcrunch-secrets-aws-secrets-manager` | Its Go module, backend configuration/parser, transport, payload behavior, and tests | AuthCrunch's category guidance plus its own `AGENTS.md` and repo-local skills |
| Host project, such as `caddy-security` | Host extension interfaces, registration, configuration integration, and runtime composition | Its plugin-development skills build on AuthCrunch's guidance and add host-specific contracts |
| Separate companion plugin, such as `caddy-security-secrets-aws-secrets-manager` | The adapter module that makes one backend usable by the host | AuthCrunch guidance, host-project guidance, backend public API evidence, and its own local skills |

Production backend development normally starts in its own repository. The
AuthCrunch `plugins/` tree provides category examples and contract fixtures; it
is not where every external backend's production source is copied. Its layout
does not create discovery, registration, or a generic runtime SDK. The
[synthetic reference contract](synthetic-reference.md) defines what belongs there.

These guidance dependencies do not dictate identical Go dependencies. A backend
can remain independent of core when its API permits; a backend implementing a
core interface may import that public package. A companion imports the backend
and the relevant host APIs. Backend production code must not depend on its host
companion. Host integration tests belong to the host/companion side, keeping
that dependency out of the backend's module.

## Load guidance from another repository

A request such as "use guidance from github.com/greenpau/go-authcrunch to build
a secrets plugin" must work without globally installed AuthCrunch skills or a
particular sibling checkout. Resolve guidance as follows:

1. Establish the active repository and read its `AGENTS.md` and local skills.
   For an empty repository, establish the category, backend, module path, and
   intended consumer from the task before generating its guidance files.
2. Locate `github.com/greenpau/go-authcrunch`. Use a user-selected checkout or
   revision when supplied; otherwise discover the repository's default branch
   and resolve it to an immutable commit. Read
   `.codex/skills/plugin-development/SKILL.md` at that revision, its blueprint,
   and the selected category's reference/skill. For secrets, read
   `.codex/skills/secrets-plugins/SKILL.md` and its task-relevant references.
3. Follow relative links against the source repository, source file directory,
   and the same revision. A reference to `../../../pkg/...` refers to AuthCrunch
   source, not to a nonexistent path in the new plugin repository. A scoped
   checkout or source archive can preserve this context; fetching individual
   files requires resolving their links explicitly.
4. Inspect the corresponding public declarations, consumers, tests, and any
   available synthetic reference. Do not assume an unpublished skill path,
   planned reference plugin, or proposed category API already exists remotely.
   If needed guidance is only in an authorized local checkout, record that source
   and its working-tree status; replace it with published immutable links before
   claiming another developer can reproduce the repository from GitHub alone.
5. Record the guidance revision in the new repository's `AGENTS.md`. Record
   supported runtime module versions separately in `go.mod` and compatibility
   guidance. Reading a newer skill does not authorize a dependency upgrade or
   make a new core API available in an older dependency.

If a required source cannot be retrieved, identify the missing repository/path
and use an available authorized checkout, or request that missing information.
Continue independent work where possible; do not invent the unavailable API or
claim the missing guidance was applied.

Apply engineering contracts to the active plugin, while preserving instruction
scope. AuthCrunch's local Make targets and release commands operate in AuthCrunch;
do not transplant them into another module. Its prohibition on editing sibling
repositories scopes work performed as a core-repository task. A separate task
explicitly creating a plugin has that plugin as its write scope and uses its own
validation commands. Reading core or host guidance does not authorize modifying
those repositories. Keep shared contracts authoritative upstream and document
only the backend's concrete binding and justified differences locally.

## Bootstrap a backend repository

An agent should be able to carry a category-specific task from an empty working
directory to a runnable module using this workflow and the blueprint:

1. Select the category and name; identify the existing public consumer API or
   the missing integration it would require. Distinguish backend functionality
   that can be built now from core capabilities still proposed. Confirm the
   module's intended import path before writing `go.mod`; a local scaffold does
   not require creating or publishing a remote repository.
2. Read the core guidance as above. Establish whether a host companion is part
   of the task. A backend can be completed and tested as a plain Go library even
   when a companion will be developed separately; scope compatibility claims
   accordingly.
3. Create `AGENTS.md` with actionable upstream and repo-local routes. Create the
   referenced local implementation skill in the same change. Put module-specific
   API/configuration, ownership, validation commands, and compatibility in that
   local skill and its references. Do not leave a route to an empty or absent file.
4. Initialize the Go module and implement the focused API, typed configuration,
   dedicated `parser` package, runtime, and controlled backend fixture using the
   blueprint. Reuse an upstream synthetic plugin as contract evidence when one
   exists; do not copy its synthetic behavior as a production backend.
5. Add external-package API/parser tests, executable examples, failure/concurrency
   cases, and a real consumer journey appropriate to the claimed integration.
   Keep the default suite independent of cloud accounts and production secrets.
6. Provide the repository's own test/build commands and CI. Pin compatible
   toolchain/dependency choices; commands must work from a fresh clone without a
   sibling checkout or unpublished `replace` directive. Development-only local
   overrides are not release compatibility evidence.
7. Write onboarding and compatibility guidance naming the backend, supported
   category operations, module version, configuration, consumer, and any companion.
   Validate local skills and their routes, run the documented checks, and report
   unimplemented consumer integration explicitly. Publication remains a separate
   action governed by the user's task.

A useful resulting layout extends the blueprint's module layout:

```text
go-authcrunch-<category>-<backend>/
    AGENTS.md
    README.md
    go.mod, go.sum
    .codex/skills/plugin-implementation/
        SKILL.md
        agents/openai.yaml
        references/                 only when useful for backend-specific detail
    config.go, client.go
    parser/
    client_test.go
    consumer_e2e_test.go
    .github/workflows/test.yml       or the project's selected CI system
```

Module naming is a convention, not discovery. Preserve existing module names
such as `go-authcrunch-ids-*`; directory category slugs need not rename published
modules. Include other files only when the backend or repository requires them.

## Backend AGENTS.md template

This is a complete routing pattern for a **new secrets backend**, not evidence
that existing external repositories already contain these instructions. For the
portable form, replace `AUTHCRUNCH_REVISION` with the inspected immutable commit
that actually contains the guidance. Use the local-draft variant below when
that source has not been published; do not substitute a commit missing the files.
For another category, replace the secrets route with the appropriate category
contract and any owning skill identified by `plugin-development`. Create the
local `plugin-implementation` skill before validating the resulting routes.

```markdown
# Repository Guidelines

This repository implements a standalone AuthCrunch secrets backend as a Go
module. Backend behavior belongs here; host integration belongs to a companion
module when one is needed.

## Shared plugin guidance

Use [plugin-development](https://github.com/greenpau/go-authcrunch/blob/AUTHCRUNCH_REVISION/.codex/skills/plugin-development/SKILL.md) to design the module, verify its consumer boundary, and follow the repository/bootstrap and development blueprints.
Use [secrets-plugins](https://github.com/greenpau/go-authcrunch/blob/AUTHCRUNCH_REVISION/.codex/skills/secrets-plugins/SKILL.md) to implement retrieval, payload validation, metadata, concurrency, and consumer acceptance for this secrets backend.

AuthCrunch guidance revision: AUTHCRUNCH_REVISION. Resolve linked files relative
to that source repository and revision. Inspect the selected API declarations;
guidance availability does not establish runtime compatibility.

## Repository implementation

Use [plugin-implementation](.codex/skills/plugin-implementation/SKILL.md) to implement this backend's API, configuration/parser, lifecycle, tests, and compatibility requirements, and to run this repository's validation commands.

Apply shared AuthCrunch contracts together with these local details. Keep the
shared contract upstream; document concrete backend differences locally. Keep
edits and commands in this repository. Core and companion repositories are
separate work unless the user's task explicitly includes them.
```

The local skill must describe the actual backend and commands, not repeat the
generic template. Its metadata must name its real skill, and its acceptance
cases must prove the selected category's meaningful behavior. Follow the active
repository's authoring tools; upstream guidance need not be installed globally.

For authorized unpublished guidance, replace the template's shared-guidance
section with this temporary local-source form. Replace `AUTHCRUNCH_CHECKOUT`
with the actual supplied path, `BASELINE_COMMIT` with its inspected HEAD, and
`CHANGED_GUIDANCE_PATHS` with the relevant changed/new paths. Keep the local
implementation route from the full template. These machine-specific routes are
usable for the draft task but must become verified immutable upstream links
before claiming portable guidance or a reproducible published scaffold.

```markdown
## Shared plugin guidance (local draft)

Use [plugin-development](AUTHCRUNCH_CHECKOUT/.codex/skills/plugin-development/SKILL.md) to design the module and follow the category and repository development contracts.
Use [secrets-plugins](AUTHCRUNCH_CHECKOUT/.codex/skills/secrets-plugins/SKILL.md) to implement this secrets backend's retrieval and consumer contract.

Guidance source: the authorized local AuthCrunch working tree at baseline
BASELINE_COMMIT, including unpublished changes in CHANGED_GUIDANCE_PATHS.
The baseline alone does not reproduce those files. Resolve linked references
inside that source checkout. Replace these draft routes with published source
revisions before declaring this repository independently reproducible.
```

## Companion host plugins

Companions are expected for many production backends. The working
[AWS backend](https://github.com/greenpau/go-authcrunch-secrets-aws-secrets-manager)
and [Caddy companion](https://github.com/greenpau/caddy-security-secrets-aws-secrets-manager)
illustrate separate repositories for reusable retrieval and host adaptation.
The existing pinned adapter sources in the plugin-development entrypoint are
implementation evidence; they do not prove a host has published the future skill
layout described here.

The host project's plugin-development skill should consume AuthCrunch's shared
plugin skill and selected category contract, then supplement them with the host's
repo-local skills. It owns host module identifiers/registration, directive or
JSON adaptation, placeholder handling, provisioning/reload/disposal, and host
test/build procedures. It must preserve backend validation, identity/authorization
boundaries, and lifecycle guarantees while defining how the host invokes them.

When developing a companion, inspect the host's actual `AGENTS.md` routes to
locate those skills. Do not guess that a particular host skill path exists. The
companion's own local skill records its exact backend-to-host binding: API/version
pair, instance/resource mapping, capability mismatches, cache/rotation adoption,
ownership, and real host acceptance. A companion is not necessarily a one-to-one
method forwarder, as the path-bound AWS adapter demonstrates.

Keep this guidance dependency directional: core defines category behavior; host
guidance adds host contracts; the companion adds concrete adapter details. Core
must remain usable without loading host guidance. Host/companion skills may link
back to shared core authority but must not create recursive task delegation
between their local skills. If contracts conflict, inspect the selected versions
and resolve or explicitly report the mismatch; host syntax cannot silently weaken
the backend contract.

Verify and record the backend module, core runtime (when used), host runtime,
companion module, and guidance revisions separately. Test a compiled host with
the companion included: parsing/registration, provisioning, real consumption,
failure, and cleanup. Backend unit tests and a successful companion build alone
do not establish host compatibility. Run those checks in the authorized host or
companion task, not by mutating a sibling checkout from a core-only task.

## Companion AGENTS.md template

Start with this routing pattern for a separate host companion. Replace
`AUTHCRUNCH_REVISION`, `HOST_PLUGIN_SKILL_URL`, and `BACKEND_REPOSITORY_URL` with
verified sources; the host-skill URL should use an immutable revision and its
actual discovered path. Replace the host route label with that skill's declared
name, and create the referenced local companion skill. The same explicitly
recorded local-draft fallback applies when an authorized core or host skill is
unpublished; a missing host skill cannot be replaced with a guessed URL.

```markdown
# Repository Guidelines

This repository adapts a standalone AuthCrunch backend to its host framework.

Use [plugin-development](https://github.com/greenpau/go-authcrunch/blob/AUTHCRUNCH_REVISION/.codex/skills/plugin-development/SKILL.md) to apply shared plugin architecture and the selected category contract.
Use [host-plugin-skill](HOST_PLUGIN_SKILL_URL) to implement the host's module registration, configuration adaptation, provisioning, lifecycle, and validation contracts.
Use [companion-implementation](.codex/skills/companion-implementation/SKILL.md) to maintain this adapter's exact API mapping, supported versions, failure behavior, and real host tests.

Inspect the selected version of the [backend repository](BACKEND_REPOSITORY_URL)
for its public API and local guidance. Resolve each upstream skill's references
in its own repository and revision. Keep shared category rules upstream, host
rules in the host project, and this module's concrete adapter details locally.

Keep changes and validation in this repository. Backend, host, and core changes
are separate tasks unless explicitly included by the user. Do not claim host
compatibility until the configured companion is exercised in a compiled host.
```

## Acceptance

- An agent given only an empty authorized plugin workspace, a category/backend,
  and the AuthCrunch repository can locate guidance, choose a supported boundary,
  create valid upstream/local routes, and produce the module and its tests.
- A second developer follows the recorded revisions from a fresh clone without
  machine-specific paths, a global AuthCrunch skill installation, or sibling
  files; the declared local commands validate the same compatibility contract.
- A category with a proposed API yields an explicit integration gap, not invented
  constructors, an inert registration call, or an unsupported-runtime claim.
- A companion applies core, host, and local guidance together and proves actual
  host use while the backend stays independent of host-framework dependencies.
- Guidance updates recheck API/version assumptions and local contracts without
  silently rewriting dependency pins or copying entire upstream skill trees.
