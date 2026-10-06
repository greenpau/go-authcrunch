# In-Repository Reference Plugins

Read this contract when adding a category reference or synthetic/mock plugin
inside `go-authcrunch`. External production plugins follow the
[separate-repository workflow](repository-workflow.md); this tree supplies
executable examples and fixtures for their shared contracts.

## Layout and implementation status

Use `plugins/<category>/<name>` for in-repository plugin implementations.
Categories use lowercase hyphenated slugs matching the
[catalog anchors](plugin-categories.md), plus `secrets`; choose a concise backend
name such as `mock`. For example, the intended secrets reference lives at
`plugins/secrets/mock`.

This is the required layout for future implementation. A path in this guide is
not proof that a plugin, constructor, parser, or category integration is present.
Inspect the working tree before naming an available reference. Establish a
runnable synthetic reference when implementing a category's plugin integration;
do not satisfy that requirement with empty directories or a forwarding stub.
A documentation-only task records the contract without claiming implementation.

```text
plugins/
    secrets/
        mock/
            doc.go
            config.go
            client.go
            client_test.go
            parser/
                config.go
                config_test.go
                config_example_test.go
            consumer_e2e_test.go
```

The filenames are a starting shape. Keep focused category behavior in the
reference package and authoritative category APIs in their owning core package.
Avoid copying production SDKs or maintaining parallel copies of external
backends. A reference plugin can use public core APIs; core production packages
must not import a mock plugin or select it by default. The directory is not a
plugin loader, a factory registry, or a promise of Go `plugin.Open` support.

Use the root Go module for in-repo references by default. A nested `go.mod` would
exclude them from the root `./...` test traversal and requires deliberately
separate dependency/CI ownership. Do not introduce one merely to resemble an
external plugin repository.

## What a synthetic plugin must prove

Implement a small deterministic backend that exercises the real category
contract without an external account. Supply synthetic data explicitly and
avoid ambient credentials, metadata services, public network calls, machine
paths, or production signing material. The package name and public description
must identify its reference/testing purpose.

The synthetic backend must be usable through its public construction and
configuration APIs, including its dedicated `parser`. Consumer tests should
import those APIs from an external test package to avoid package-private helpers.
That package is still inside the core module and can legally import its
`internal` tree; prohibit such imports in portable consumer examples explicitly.
To prove standalone usability, also compile and exercise the public workflow
from an isolated external-module fixture launched by the root test suite. Keep
that fixture in test-owned temporary storage; a test-local replacement of the
core module validates this checkout, not published-module compatibility.

Bind the reference to the actual public consumer. If that consumer needs a new
API, implement and test the integration or state the narrower scope; a synthetic
method returning success does not establish category support.

Cover the category's meaningful success and failure behavior, config validation,
cancellation for blocking operations, value ownership, concurrency, and cleanup
when resources exist. Keep fixture controls deterministic and instance-owned;
avoid mutable global fault switches or unbounded sleeps. Expose only the controls
needed to exercise a real contract, and keep test-only helpers out of production
backend API designs. An explicitly synthetic module is allowed to model failures
that a production backend would receive from its transport.

For the first **secrets** reference, the useful contract is:

- A typed config and reusable parser define a named synthetic record and its
  supported value shapes. Validate supplied fields without a network request.
- Public retrieval preserves exact accepted types, returns independent snapshots,
  and reports missing records/keys explicitly. Define the supported copy policy
  for nested values rather than claiming arbitrary Go values are immutable.
- Metadata excludes synthetic secret values. Required-string consumers reject
  invalid types and empty values without panic or diagnostic disclosure.
- Record versus path selection is explicit. A consumer adapter can bind a path
  when required; do not claim the existing static and AWS signatures are identical.
- A consumer journey runs parser → reference backend → validated typed application
  → the claimed AuthCrunch behavior using only synthetic inputs. Exercise a
  meaningful failure through that same boundary. Retrieval-only evidence remains
  retrieval-only until real AuthCrunch consumption is covered.

The [secrets owner](../../secrets-plugins/SKILL.md) defines the category's existing
APIs and compatibility limits. Other references select the corresponding
[category acceptance scenarios](plugin-categories.md): for example, refresh
storage must enforce atomic rotation/replay semantics and an authorization
reference must not turn errors into permission. Proposed categories still need
their public consuming APIs; placing code under `plugins/` does not create them.

## Include the reference in repository validation

When the first package under `plugins/` is implemented, check the root automation
and scanners as part of that implementation. The current Makefile's `linter`
target explicitly enumerates `.`, `cmd`, `internal`, and `pkg`; it does not yet
include `plugins`. Extend that maintained scope and its automation fixture when
adding the tree. Verify test discovery, config/tag checks, diagnostics, and any
other source-tree allowlists against the actual new package.

The [repository testing requirements](../../testing-and-ci/SKILL.md) and
[automation contract](../../scripts-and-automation/SKILL.md) govern those changes.
Run the relevant race-enabled consumer tests and required checks; do not create
a reference that CI silently omits. Keep real-cloud tests optional and separate
from the default synthetic suite when a future external backend needs them.

At completion, link the implemented package and its exact public entry points
from the owning category guidance. Include a supported external-consumer usage
example and update availability claims. Preserve the separation between this
reference, a standalone production module, and a host companion's acceptance.
