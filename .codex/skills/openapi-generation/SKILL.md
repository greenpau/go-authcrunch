---
name: openapi-generation
description: "Maintain AuthCrunch's YAML HTTP contract, deterministic JSON/YAML exports, Scalar reference and local server. Use after HTTP-facing source/configuration changes, source-review drift, or API reference tooling changes."
---

# OpenAPI Generation

## Own the HTTP reference

Keep canonical OpenAPI 3.1.1 YAML in `assets/openapi/content/openapi.yaml`, with
local references into `paths/` and `components/`. `make openapi` validates and
bundles it into ignored `assets/openapi/generated/openapi.json`. Never hand-edit
JSON or reverse-generate authored YAML. Preserve its Git ignore and VS Code
files/search/watcher exclusions.

The contract describes this checkout's authentication portals and authorization
policies, regardless of embedding HTTP server. It creates no runtime routes.
Host configuration/management, arbitrary protected application resources,
static assets and unfinished placeholders are outside its scope. Trace the
native dispatchers and runtime; do not resolve AuthCrunch as its own dependency
or assume a sibling consumer's wrapper behavior.

`VERSION` owns `info.version`. `make version-check` rejects drift;
`make version-sync` updates the YAML and existing Go metadata projections.
Retain the single LF-delimited `info:` block and plain two-space
`version: 1.<minor>.<patch>` line expected by `assets/scripts/version.py`.
Generation/serving/checks never synchronize source implicitly. Checked and fast
patch/minor release workflows synchronize and commit YAML; JSON stays generated.
A documentation change does not authorize a version bump or release.

Read [source review](references/source-review.md) to trace operations, route
ownership, credential boundaries, availability and validation evidence. Read
[field contracts](references/field-contracts.md) to enrich units, normalization,
validators, encodings, state-dependent checks and returned records.

## Evaluate every HTTP-facing change

Before completing changes to handlers, dispatch, configuration gates, identity
payloads, cookies, token/session lifecycle, OAuth/OIDC/SAML, serialization or
HTTP host integration, compare resulting behavior with the YAML. Update paths,
methods, payloads, media types, statuses, headers, security, examples and feature
availability in the same change, together with owning skills and tests. Review
ordering, revocation, expiry and consent even when the JSON shape stays stable.

`assets/openapi/reviewed-sources.yaml` fingerprints local contract inputs.
Generation, ordinary Go tests and CI reject added/changed/removed inputs.
This is a review gate, not proof of exhaustive runtime coverage. Expand
`internal/openapi/sources.go` for new owners. External crypto/parser dependency
changes also require review even when wrapper hashes stay unchanged.

1. Read each changed input and its callers, serializers, validators and tests.
2. Update YAML and affected contract tests. Explain changes with no HTTP effect
   in the change description; accurate YAML need not receive artificial edits.
3. Write a candidate inventory and inspect its diff:

   ```bash
   mkdir -p tmp/openapi
   go run -mod=readonly ./cmd/openapi sources > tmp/openapi/reviewed-sources.yaml
   diff -u assets/openapi/reviewed-sources.yaml tmp/openapi/reviewed-sources.yaml
   ```

4. Copy the reviewed candidate to the tracked inventory only after semantic
   review. Never refresh fingerprints automatically in CI to conceal drift.

Logging-only edits to fingerprinted handlers still require this review and an
inventory update in the same PR. If requests, responses and authentication
decisions are unchanged, retain the existing YAML contract and record that
finding in the change description. Refresh only the reviewed entries and run
`make ci-quality` and `make openapi-test` before publishing the correction.

The inventory uses module identity and repository-relative paths, without
checkout paths, timestamps or release version. Only `versioned` metadata
literals in `cmd/authdb/main.go` and `pkg/identity/database.go` are normalized;
other bytes in those files remain protected. Thus ordinary release projection
changes do not create false HTTP review failures.

## Author precise contracts

Use one path item per file, registered reusable components and local `.yaml`
references under `content/`. Quote response codes. Reject remote refs, symlinks,
anchors/aliases, duplicate keys, multiple documents, non-string keys, orphan
YAML, `$id` and dynamic references. The bundler preserves recursive components.
Apply reference/resource rules only in schema and OpenAPI object positions.
Payload examples, defaults, enum/const values and extensions are literal data;
fields named `$ref` or `$id` inside them must survive unchanged. Schema property
names are also data, but their associated schemas still require validation and
reference resolution, including property names starting with `x-`.
Paths, Responses and Components extensions follow the same literal-data rule,
including the initial component-registration pass. Extension-only maps do not
supply a required path or response.

Each operation needs a unique stable ID, one declared tag, summary, description,
explicit security, responses and repository-relative `x-source-files` evidence.
Keep summaries nonempty, plain-language and unique across the entire reference,
including different tags. Generation rejects collisions after case normalization and
whitespace normalization. Preserve stable operation IDs when improving labels.
Name the actual action: opening a form versus submitting it, displaying a login
challenge versus answering it, receiving an OAuth callback versus bridging a
URL fragment, and reviewing consent versus submitting a decision. Where two
methods perform the same action, use an accurate transport qualifier such as
GET/POST. Identify each OPTIONS endpoint's target; a repeated generic CORS label
is ambiguous. Do not imply immediate account activation or a default realm.
Body credentials, sandbox state, browser evidence, CSRF, consent and feature
flags are additional conditions beyond reusable OpenAPI security schemes.
Keep portal access, profile sessions, portal refresh, OP tokens, cross-device
proof and direct OAuth sessions distinct.

Describe units, omission/null/empty behavior, normalization, ownership and
conditional validation. Trace handlers into constructors and state consumers.
JSON Schema string lengths count characters; Go string limits often count UTF-8
bytes. Use descriptive byte limits rather than invented character ceilings.
Do not turn timestamps into unexplained integers, durations into timestamps,
opaque credentials into generic strings, or backend-dependent flags into
universal promises. Preserve actual media/serialization quirks. Trace returned
records separately, including nested hashes/secrets and omitted fields.

Keep `Authentication Portal` for login/navigation/portal sessions,
`Cross-Device Sign-In`, and `External Authentication` for federation/SSO/direct
OAuth. Grouping does not merge credential boundaries.

Arrange categories by workflow: Registration, Authentication Portal, External
Authentication, Cross-Device Sign-In, Profile, Discovery, OpenID Connect,
Administration, then System. Keep the root `paths` mapping grouped in that order.
Within a journey, put entry/discovery before authentication or submission,
continuation before completion, session use before refresh, and logout/revocation
last. Administration starts with metadata and realm discovery, then realm/user
inspection and account management, followed by reload and private-key export.
Keep alternate protocols together and HEAD/OPTIONS next to their primary route.
Registration begins at `/register/{realm}` and proceeds to its acknowledgement
form and code submission. The bare `/register` route does not select a default
realm: unauthenticated requests fail with 400, except its GET returns 503 when
registration is disabled; authenticated users redirect to the portal. Keep these
missing-realm entries after the working flow and identify their rejection in
their labels. Opening the acknowledgement form does not consume confirmation.

Author operation order in each path item's YAML mapping. The bundler preserves
root path order and path-item field order through inline items, referenced items
and non-overlapping reference siblings; references splice at their authored
position. JSON and generated YAML retain that order without changing contracts,
schema encoding or literal extension data. JSON object order is presentation
metadata, not an HTTP requirement; other viewers can choose their own sorting.
The pinned Scalar reference must show the authored category and operation order.
Do not enable alphabetical or method sorting over the workflow sequence.

Every operation inherits `{origin}{portalBasePath}`. Defaults are
`https://auth.myfiosgateway.com:8443` and `/auth`. Direct OAuth paths are
`/oauth2/authorization-code-callback` and `/oauth2/logout`; realm federation
uses `/oauth2/{realm}`. With `/auth`, all start with `/auth/oauth2/`.
Path/operation server overrides are rejected. Configure the direct policy's
full base path to match the mount plus `/oauth2`; runtime policy defaults are
independent of portal mounting. Hosts must dispatch its exact callback/logout
to the gatekeeper before catch-all portal routes and preserve handled responses.
Keep realm routes separate and avoid exact-endpoint name collisions.

## Generate, serve and view

```bash
make openapi
make openapi-check
make openapi-artifact
make serve-openapi
make serve-openapi OPENAPI_ADDR=127.0.0.1:8090
```

Generation uses pinned Go dependencies and offline OAS/schema validation;
`make dep` prepares dependencies. No Node or running auth server is required.
It validates before atomic replacement, retains a valid old bundle on failure
and leaves identical output untouched. `openapi-check` requires fresh generated
JSON, so generate first in a clean checkout.

`make openapi-artifact` invokes the CLI's `artifact` action and writes standalone
`openapi.json` and block-style `openapi.yaml` under
`assets/openapi/generated/artifact/`. Both represent the same validated bundle;
component references stay internal, and YAML preserves scalar types, exact
numeric values and Unicode line-break characters in strings and schema patterns.
Escape JSON's literal NEL/LS/PS before YAML parsing. Preserve quoted strings when
switching collections to block style: this prevents line-break normalization and
YAML 1.1 consumers from reinterpreting values such as `on` or `12:34`.
This YAML is a generated distribution, not an authoring source.
Source-review and VERSION gates run before export. Each file is replaced
atomically; consumers publish only after both writes succeed.

The test workflow's quality job uploads that directory separately as
`go-authcrunch_openapi_<artifact-id>`, after quality checks and source-cleanliness
verification succeed. It uses selection's shared artifact identity, retains the
artifact for 14 days, replaces it on rerun, and fails if output is missing.
Ordinary non-code/release-owned skips retain their existing selection behavior.
Do not mix these specifications into the coverage shard/merge artifacts.

The local server regenerates before listening, defaults to loopback port 8080,
prints its URL and stops on Ctrl-C/SIGTERM. It serves only the HTML/bootstrap,
bundle and YAML without directory/private-file exposure; responses disable
caching. Asset paths reject symlinks in both files and parent directories,
including aliases that stay inside the documentation root. Keep this local
documentation tree under the operator's control; it is not a sandbox for
concurrent untrusted filesystem writers. It does not proxy requests, bypass
CORS or enable runtime features.
Browser same-origin authentication must run at the actual portal origin.

The viewer persists valid origin/mount edits in localStorage under
`authcrunch.openapi.portal-server`, scoped to its browser origin including port.
Restore before rendering, preserve empty mounts, reject malformed origins/paths
and tolerate missing/corrupt/unavailable storage. Persist no credentials or whole
viewer state. Scalar variable edits require bootstrap input-event capture in
this pinned release. Empty mounts omit the in-memory server placeholder while
retaining its editable field; typing must not remount the focused input.

Pin Scalar's published standalone bundle at an exact CDN version with SHA-384
SRI; verify bytes on upgrade. Keep telemetry, AI/MCP and credential persistence
disabled. Clients are Shell/curl (default), PowerShell Invoke-RestMethod and
Invoke-WebRequest, Python http.client (`python/python3`) and requests. Validate
actual menus/snippets, not just the configuration object. Keep responsive
heading controls within the viewport instead of hiding overflow.

Keep relative, credential-free, cache-busted spec fetching and visible load
errors/file-URL instructions. After changing `scalar.js`, update its query in
`index.html` to the first 12 SHA-256 hex digits.

## Validate changes

```bash
make openapi-test
make openapi
make openapi-check
make openapi-browser-test
```

`openapi-test` runs race-enabled bundler/server/unit tests, real Make generation
and serving in an isolated local checkout, native TLS portal/policy contract
journeys and Node bootstrap tests. Contracts consume authored schema pointers;
never replace real password/provider/session flows with fabricated responses.
The executable fixture reads the real workflow build command/upload directory,
verifies JSON/YAML equivalence and standalone schema compilation, and rejects
source/version drift without replacing a previously valid artifact. Unit cases
cover exact scalar values, repeat generation, invalid input and symlink targets.
Ordering units also cover inline paths, reference chains, escaped pointers,
reference siblings and preservation in both exported formats.
Label units reject blank and duplicate summaries across methods, paths and tags,
including case/whitespace variants. CLI E2E verifies that rejected label edits
preserve the previous reference and both artifact files. Browser E2E compares
every visible operation label to the spec and checks uniqueness in navigation;
distinct operation IDs or link URLs alone do not establish readable labels.
Its Go phases use `make test` and the resource guard, retaining separate tested
reports under `COVERAGE_DIR/openapi-tools` and `COVERAGE_DIR/openapi-contracts`.
Either failing phase stops the target before later phases. Native contract tests
use the `TestE2EOpenAPIContract` prefix, including the scoped native-journey hook.
The Make-launched process-group fixture lives in `cmd/openapi/e2e_unix_test.go`
and runs on POSIX hosts; portable CLI unit tests remain in `main_test.go` so
Windows test builds do not import Unix-only process APIs.
Read server readiness from the `OpenAPI reference:` message, not the first
stdout line: recursive Make can announce directories before the server binds.
The E2E fixture forces `--print-directory` to exercise this on local and CI
runs. Keep startup waits bounded and propagate premature EOF/read failures.
Existing independent feature journeys retain their deeper state/security checks.
Sampling is not exhaustive branch coverage or official OP certification.
Official conformance remains separate and opt-in.

`openapi-browser-test` needs Node 24 and Chrome/Chromium, or
`AUTHCRUNCH_TEST_BROWSER`. It checks the actual SRI-pinned Scalar bundle, VERSION,
five clients, every operation's mounted request URL, persistent settings/reload,
empty/corrupt storage, exact category/operation navigation order, field semantics
and desktop/mobile layout. It uses the resource guard with evidence in
`COVERAGE_DIR/openapi-browser`.
Verified CDN bytes and screenshots remain in `tmp/openapi`.
For copied Go consumer/migration sources under that directory, follow
[Go discovery isolation](../testing-and-ci/SKILL.md#test-lifecycle); Git ignore
alone does not keep temporary packages out of `go test ./...`.

`make ci-quality` generates, checks freshness and runs bootstrap tests; the full
Go suite includes generator/CLI/native contracts. CI never refreshes the review
record. Update owning skills and validate links/metadata before handoff.

The native contract matrix adds real login work to the complete serial gate.
If clean completed-package timings exhaust the default 40-minute workflow
watchdog, preserve that run's evidence and use a bounded override such as
`TEST_WALL_TIMEOUT=3600 make ci-check`. Keep the memory limit, Go package
deadlines and full test inventory intact; distinguish deadline exhaustion
from a failing or stalled test before changing the workflow budget.
