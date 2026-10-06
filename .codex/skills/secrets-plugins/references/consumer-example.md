# Plain Go Consumer Example

This complete package illustrates an adapter over the **existing** modules.
`Reader`, `NewAWSReader`, `NewStaticReader`, and `RequireString` below are example
consumer code, not APIs exported by go-authcrunch or either plugin. No generic
registration API is required. The example uses `any`, Go's alias for
`interface{}`; the method signatures remain compatible with the original APIs.

The static client already satisfies the record-reader interface. The AWS
adapter binds one path, serializes calls to protect the reference client's lazy
initialization, and uses full-record retrieval to avoid its unchecked field
cast. The example owns the AWS client privately; do not expose it for concurrent
calls that bypass the mutex. Serialization is deliberately simple and can limit
throughput; a new backend should establish safe construction and sharing in its
own runtime rather than inheriting this workaround.

```go
package pluginexample

import (
	"context"
	"errors"
	"sync"

	awssecrets "github.com/greenpau/go-authcrunch-secrets-aws-secrets-manager"
	staticsecrets "github.com/greenpau/go-authcrunch-secrets-static-secrets-manager"
)

// Reader is owned by the consumer and represents one selected record.
type Reader interface {
	GetSecret(context.Context) (map[string]any, error)
	GetSecretByKey(context.Context, string) (any, error)
	GetConfig(context.Context) map[string]any
}

var _ Reader = (staticsecrets.Client)(nil)
var _ Reader = (*boundAWS)(nil)

type boundAWS struct {
	mu     sync.Mutex
	client awssecrets.Client
	path   string
}

// NewStaticReader creates a record containing only synthetic example data.
func NewStaticReader(ctx context.Context) (Reader, error) {
	return staticsecrets.NewClient(ctx, "example", map[string]any{
		"username": "example-user",
	})
}

// NewAWSReader binds a backend resource to one consumer instance.
func NewAWSReader(ctx context.Context, id, region, path string) (Reader, error) {
	if id == "" || region == "" || path == "" {
		return nil, errors.New("secret reader requires id, region, and path")
	}
	client, err := awssecrets.NewClient(ctx, id, region)
	if err != nil {
		return nil, err
	}
	return &boundAWS{client: client, path: path}, nil
}

func (r *boundAWS) GetSecret(ctx context.Context) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.client.GetSecret(ctx, r.path)
}

func (r *boundAWS) GetSecretByKey(ctx context.Context, key string) (any, error) {
	record, err := r.GetSecret(ctx)
	if err != nil {
		return nil, err
	}
	value, ok := record[key]
	if !ok {
		return nil, errors.New("required secret field is missing")
	}
	return value, nil
}

func (r *boundAWS) GetConfig(ctx context.Context) map[string]any {
	// The library returns fresh metadata; retrieved values are excluded.
	metadata := r.client.GetConfig(ctx)
	metadata["path"] = r.path
	return metadata
}

// RequireString validates one field from an already retrieved snapshot.
func RequireString(record map[string]any, key string) (string, error) {
	raw, ok := record[key]
	if !ok {
		return "", errors.New("required secret field is missing")
	}
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", errors.New("required secret field must be a nonempty string")
	}
	return value, nil
}
```

Construct a static reader, call `GetSecret`, then `RequireString(record,
"username")`; the synthetic result is `example-user`. For AWS, use a bounded
context to construct/read the bound client and apply `RequireString` to each
required field from **one** returned record. The example does not log values or
include them in validation errors. It does not copy a static reader's map;
callers must keep it immutable, as specified by the existing static API.

The mutex waits for an earlier call to finish before observing cancellation.
Give every remote call a deadline. If prompt cancellation while queued or
parallel throughput is required, implement and test a context-aware admission
policy or an eagerly initialized concurrency-safe backend. Those are additional
contracts, not promises made by this example.

## Verify without a cloud account

In an isolated example module, pin the inspected plugin revisions from
[provider contracts](provider-contracts.md). Copy the Go block into a source
file and add external consumer tests. Keep the root module's dependencies
unchanged when verifying documentation examples.

Isolate AWS configuration **before constructing** the reader. Run tests in a
child process with inherited `AWS_*` settings removed, explicit empty temporary
files for `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`,
`AWS_EC2_METADATA_DISABLED=true`, and synthetic `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`. Keep the developer's environment and configuration files
unchanged. `NewClient` loads SDK configuration before test hooks can be installed;
hooks alone do not isolate profile, CA-bundle, web-identity, or defaults-mode
behavior during construction.

For AWS transport tests, the upstream module supports an `aws.HTTPClient` and
`aws.CredentialsProvider`. Tests in the example package can configure those
hooks on the privately held client **before first retrieval**. Return an AWS
response envelope such as `{"SecretString":"{\"username\":\"example-user\"}"}`;
this exercises real SDK request construction and decoding without contacting
AWS or using real credentials.

Verify the outbound `SecretId` and `VersionStage`, exact string preservation,
missing and non-string fields, caller cancellation, repeated retrieval after
changed fixture data, concurrent first use through the adapter, and metadata
that excludes a synthetic secret canary. Include a public-consumer journey
constructing and reading a real static client. Run under the race detector.

This example establishes retrieval and adaptation only. To claim AuthCrunch
integration, feed validated values into the relevant public configuration/parser
API and exercise its real consuming workflow. To claim host-module integration,
separately prove registration and provisioning in that host. Neither follows
from compiling this example.
