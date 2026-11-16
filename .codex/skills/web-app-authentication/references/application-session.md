# Application session, navigation and authorization

## A verified app session

The application needs a same-origin, noncached way to obtain its current verified
identity and permissions. Reuse an existing session endpoint if its contract is
adequate. Otherwise implement a backend adapter; AuthCrunch does not provide an
app-specific `/api/session` endpoint or a universal CSRF scheme.

An example app-owned response contract, to adapt rather than copy blindly:

```ts
type ApplicationSession = {
  accountKey: string;       // server-derived stable account identity/namespace
  sessionId?: string;      // verified portal sid, when this is a refresh family
  accessExpiresAt: number; // Unix seconds from verified access evidence
  serverTime: number;      // Unix seconds, or use a fresh trusted Date header
  permissions: string[];  // app permissions resolved by the server
  csrf?: string;          // app-issued anti-CSRF value, when its protocol needs it
};
```

This is a **design example**, not an AuthCrunch wire type. A browser adapter maps
an implemented app response into it. Optional `sessionId` does not mean every
login is renewable. Model capability explicitly in trusted deployment/app
configuration and validate family evidence before using portal refresh.

`accountKey` includes the server's immutable user identity and relevant trusted
issuer/realm/tenant namespace. Do not use display name, email, token `jti` or
refresh-family `sid` as the account lifetime. If available claims do not expose
an adequate stable identity, add an authenticated server mapping. Never invent
one by decoding an unverified JWT. Application authorization remains server-side;
client permissions only control affordances.

The app session endpoint must return only intended public identity metadata,
never raw credentials or arbitrary private claims. Keep any CSRF value in memory,
not the shared expiry journal. Bind anti-CSRF checks to the app's actual session
contract, validate browser origin for credentialed writes, and require a fresh
session response after cookie rotation when request credentials depend on the
access token. Merely copying `X-Authcrunch-Refresh` onto business APIs does not
protect them; that header belongs to the portal transport.

## Portal probe versus app session

`GET <base>/whoami?probe=true`, with **exact** `Accept: application/json`,
`credentials: same-origin` and `cache: no-store`, is the existing portal probe.
Authenticated JSON includes `authenticated: true`, signed claims such as `exp`
and, for refresh-enabled sessions, `sid`. Missing/expired credentials produce
`401`. Validate response shape; HTML or a redirect is not session success.

This probe establishes the current portal family for the compatible browser
coordinator. Then load the app session for app identity/permissions and match its
verified family when applicable. The app endpoint cannot silently replace the
native probe without an equivalent verified-family contract. `probe=login` is a
different login-page check with stored portal-session requirements. Ordinary app
identity does not authorize profile, document or other privileged portal APIs.

Evidence: [whoami API](../../../../assets/openapi/content/paths/whoami.yaml),
[JSON handler](../../../../pkg/authn/handle_json_whoami.go), and
[profile authority](../../authentication-portal-profile/SKILL.md).

## Account and request lifetime

Separate three concepts: stable account identity; login-family identity; and a
request generation that changes whenever old work can no longer commit. A rotated
access `jti` changes request credentials, not the account. A new family requires
reverification and fencing of old requests even if it ultimately maps to the same
account. Preserve permitted same-account drafts deliberately; never leak a prior
account's cache, preferences or form state into a different account.

Capture an expected account and generation when starting app work. On response,
commit only if they still match. Cancel obsolete reads, clear account-owned caches
on identity changes, and suppress late success, error and `401` handlers from the
old generation. Cancellation alone is insufficient because a response may already
be completing. Revalidate permissions after renewal and handle changed access.

Distinguish the account lifetime fence from the credential revision used to reject
stale authentication errors. A same-account rotation during preflight may refresh
CSRF and the dispatch ticket without invalidating the user's draft. Capture the
response ticket after that preflight; never rebind an old account's operation to
whichever account happens to be current. Use separate counters when one generation
cannot express both rules without rejecting ordinary renewal or accepting stale work.

For writes, the server must reject an unexpected authenticated account **before
mutation**. An app-defined expected-account header/body field is a comparison
against verified identity, never an identity source. Combine this with CSRF and
server idempotency where appropriate. Browser cookies may change between checking
a form and sending its request; frontend checks alone cannot prevent a stale
account's form from being submitted as a newly signed-in account.

## Navigation and logout

- Bootstrap the session/renewal controller before route guards decide to sign in.
  Use a loading/recovery view while identity is unknown. Do not redirect from a
  component rendering a stale `null` user during a successful renewal.
- Preserve a validated return destination through intentional login. Resolve it
  against the configured origin and allowlisted app mounts; reject cross-origin,
  protocol-relative, credential-bearing and malformed URLs. Revalidate after login
  against app permissions. Do not pass raw `window.location` to a redirect sink.
- Keep login/callback/recovery routes outside guards that redirect to themselves.
  Bound automatic recovery and report repeated failures rather than navigating in
  a loop. Use the host's implemented continuation parameter, not an invented one.
- Attempt safe renewal before fresh login. For portal reauthentication, native
  recovery uses `<base>/login?fresh=1`; `fresh=1` intentionally avoids recycling the
  failed family. It is not an ordinary proactive renewal endpoint. Preserve a
  deep link using a validated app/host mechanism.
- Explicit sign-out uses the selected protocol's real revocation operation and
  waits for acknowledgement. Portal GET logout may be a confirmation page;
  navigation to it is not proof of revocation. Publish the signed-out UI only when
  the server confirms, or clearly label an unconfirmed failure and offer retry.
- After confirmed logout, stop renewal, invalidate private app state and notify
  other same-origin consumers. Show an intentional signed-out state instead of
  automatically sending the user back through SSO. Provider-wide logout and
  revocation of every application session are separate, explicitly supported
  operations; never claim them from clearing one cookie.
