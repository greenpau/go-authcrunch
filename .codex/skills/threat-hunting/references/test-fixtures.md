# Test-only CodeQL exceptions

A test-like filename or scanner classification does not establish trust. Trace
the caller, input ownership and packaging before accepting a finding, and keep
each exception specific to the reviewed rule and source boundary.

## Documents browser request assertions

Accept `js/regex-injection` only for sinks in exactly
`pkg/authn/ui/testdata/documents_browser_e2e.cjs`. This Node driver is invoked by
`runDocumentsBrowserEncryption` in `pkg/authn/documents_browser_e2e_test.go`.
The Go E2E harness supplies the portal mount as a command-line argument. The
driver combines that mount with its fixture-owned endpoint patterns to assert
the browser's outgoing Documents request paths. No remote caller controls that
argument in the supported test workflow. The driver's `testdata` directory is
outside the UI asset embedding roots and is not served as portal application code.

The upstream taint trace from the command line to a regex is real; this is an
accepted test-only use, not a claim that command-line strings are sanitized.
The exception must not normalize or globally sanitize the source, remove the
file from extraction, exempt other test data, or disable regex-injection checks
in runtime code. Other rules still inspect this file, and data from it remains
subject to regex-injection analysis at sinks elsewhere.

If the driver becomes deployable code or its argument acquires a remote input
path, reassess or remove the exception. Renaming or moving the file must restore
the finding until the new boundary is reviewed; do not replace path equality
with a suffix or directory match to avoid that review.

The [CodeQL workflow](../../scripts-and-automation/references/codeql.md#javascript-test-driver-exception)
owns query replacement, locked dependencies, local scans and CI verification.
Its real scanner regression must report the actual driver under the upstream
suite, remove only that rule/file finding under the configured suite, and retain
neighboring, runtime, lookalike, cross-file and same-file/other-rule controls.
Passing a local scan does not establish hosted closure; verify a later analysis
of the pushed configuration. Do not silently dismiss the hosted alert instead
of implementing and validating the requested repository exception.
