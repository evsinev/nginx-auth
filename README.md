nginx-auth
==========

Requires **JDK 21**.

## Build

```bash
mvn package
java -jar target/nginx-auth-*-jar-with-dependencies.jar
```

## Releasing

Push a version tag. GitHub Actions builds the runnable jar and publishes a GitHub Release:

```bash
git tag 1.0-7
git push origin 1.0-7
```

The tag name is the release version (`v1.0-7` is also accepted; the leading `v` is stripped). The asset is `nginx-auth-<version>.jar`.

## Overview
nginx-auth is a Java-based authentication service designed to add user authentication capabilities to nginx locations. 
This service provides a secure way to protect your nginx-hosted web applications with username/password/otp authentication.

## Features
- User authentication for nginx locations
- Integration with LDAP for user management
- Web server implementation using Jetty
- Support for password change functionality
- OTP
- WebAuthn (security keys, passkeys) as a phishing-resistant second factor, with per-group and per-location policy


## Nginx Configuration Examples

### nginx using internal section

```nginx configuration
    location /auth {
        proxy_set_header Host              $host:$server_port;
        proxy_set_header x-Forwarded-proto $scheme;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_pass http://127.0.0.1:9091;
    }
    
    location /srvlog {
        proxy_set_header Host              $host:$server_port;
        proxy_set_header x-Forwarded-proto $scheme;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_pass http://127.0.0.1:9091;
    }
    
    location /internal-srvlog {
        proxy_set_header Host              $host:$server_port;
        proxy_set_header x-Forwarded-proto $scheme;
        proxy_set_header X-Real-IP         $remote_addr;
        
        internal;
        proxy_set_header nginx_location "/internal-srvlog";
        
        proxy_pass http://127.0.0.1:9091/srvlog;
    }
```

### nginx using auth_request

`back` must be a relative path on the same host. An external auth domain is not supported.

```nginx configuration
    location /auth {
        proxy_set_header Host              $host:$server_port;
        proxy_set_header x-Forwarded-proto $scheme;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_pass http://127.0.0.1:9091;
    }

    location /srvlog {
        proxy_set_header Host              $host:$server_port;
        proxy_set_header x-Forwarded-proto $scheme;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_pass http://127.0.0.1:9091;

        auth_request            http://127.0.0.1:9091/auth/nginx-auth-request-check;
        proxy_pass_request_body off;
        error_page              401 @error401;
    }
    
    location @error401 {
      # In place of a 401 error, we rewrite to a 302 that shows the login page
      return 302 /auth?back=$request_uri;
    }
```

nginx **must** overwrite `X-Real-IP`. If that header is missing, IP throttle is skipped and only the per-username limit applies (otherwise every client behind nginx shares `127.0.0.1`). Use `limit_req` in nginx in addition to the in-process limiter.

### Identity headers for the backend

On 200 `/auth/nginx-auth-request-check` returns who is logged in, so nginx can pass it to the backend.
The example below uses `/nginx-auth-request-check` and `@login` from
[nginx with login context and policy id](#nginx-with-login-context-and-policy-id).

- `X-Auth-User`: the LDAP `uid` (`[A-Za-z0-9][A-Za-z0-9._@-]{0,127}`). With `WEBAUTHN_ENABLED=false` it is
  the login name as typed, since that mode does not read the directory entry.
- `X-Auth-Groups`: comma-separated short names of the groups, the leftmost `cn` of each `memberOf` DN
  (`cn=wk-admins,ou=groups,…` → `wk-admins`), without duplicates. Only with `WEBAUTHN_ENABLED=true`; groups
  are read at login and stay until the next login.

A value that cannot go into a header safely is dropped with a WARN, never escaped: no `X-Auth-User` for such
a uid, and such a group is left out (`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; a `cn` with a comma, a space or
non-ASCII). No groups — no `X-Auth-Groups`. 401 and 403 carry no identity. Header names are set by
`AUTH_REQUEST_USER_HEADER` / `AUTH_REQUEST_GROUPS_HEADER`; an empty value turns the header off.

```nginx
location ^~ /wellknown-ui/ {
    auth_request     /nginx-auth-request-check;
    auth_request_set $login_ctx   $upstream_http_x_login_context;
    auth_request_set $auth_user   $upstream_http_x_auth_user;
    auth_request_set $auth_groups $upstream_http_x_auth_groups;
    error_page       401 = @login;

    proxy_pass       http://127.0.0.1:27102/;
    # always overwrite: client X-Auth-* never reach the backend
    proxy_set_header X-Auth-User   $auth_user;
    proxy_set_header X-Auth-Groups $auth_groups;
}
```

nginx **must** overwrite both headers in every location that passes them. `proxy_set_header` with an empty
variable drops the header, so the backend gets either the value from nginx-auth or nothing. Without
`auth_request_set` the headers stay in the subrequest and go nowhere.

### LDAP password policy

Limiter thresholds and LDAP ppolicy must be tuned together. The limiter only sees nginx-auth traffic; other LDAP clients still increment the same failure counter.

Recommended starting point:

```
pwdMaxFailure           = 5–10
pwdFailureCountInterval = 10–15 min   (not 0: 0 means the counter never resets)
pwdLockoutDuration      = 10–30 min   (not 0: 0 means permanent lock)
```

Coordination rule:

- `LOGIN_MAX_FAILURES < pwdMaxFailure`
- `LOGIN_LOCKOUT_SECONDS >= pwdFailureCountInterval`

When both hold, nginx-auth cannot drive the LDAP counter to lockout. Failures are counted per username across all IPs; a successful bind clears that username counter (same as LDAP `pwdFailureTime`). `LOGIN_IP_MAX_FAILURES` is stuffing protection and is not part of this math.

A throttled request is rejected immediately. A wrong password still waits for the LDAP round-trip, so response time can show that the limiter fired. The form body and HTTP status stay `Authentication failed`.

### Edge protection

Put a rate limit in front of `POST /auth/login`. Cloudflare example: 5 requests per minute per IP, action block for 10 minutes; optionally Turnstile on the form.

nginx example:

```nginx
limit_req_zone $binary_remote_addr zone=auth_login:10m rate=5r/m;
location = /auth/login { limit_req zone=auth_login burst=5 nodelay; proxy_pass http://127.0.0.1:9091; }
```

## WebAuthn second factor

With `WEBAUTHN_ENABLED=true` the LDAP password stays the first factor and a WebAuthn assertion becomes the
second one:

```text
LDAP username + password → WebAuthn assertion → AUTH_TOKEN
```

A session records how it was created:

| authenticationMethod | How                                                     |
|----------------------|---------------------------------------------------------|
| `LDAP_ONLY`          | password only (`OTP_ENABLED=false`, no WebAuthn needed) |
| `LDAP_TOTP`          | password + TOTP code                                    |
| `LDAP_WEBAUTHN`      | password + security key / passkey                       |

After the password the second factor is chosen like this:

1. the policy requires WebAuthn → security key; without a usable key only an enrollment secret helps (see Recovery);
2. a TOTP code was entered (and the policy allows TOTP) → `LDAP_TOTP`;
3. the user has a security key → WebAuthn;
4. `OTP_ENABLED=true` → "Verification code is empty";
5. otherwise `LDAP_ONLY`.

A failed WebAuthn attempt never falls back to TOTP. Users register keys at `/auth/credentials` after logging
in. The first key can be registered from any session (bootstrap) unless the user's group requires WebAuthn;
adding another key or removing one requires confirming with an existing key.

Keys are created with `residentKey=required` and `userVerification=required` (ready for passwordless login
later). Hardware keys therefore ask for a PIN and use one discoverable-credential slot (YubiKey 5: 25–100
slots). Tell hardware key users in advance.

`WEBAUTHN_ENABLED=false` (default) keeps the previous behaviour.

### RP ID and origins

```text
WEBAUTHN_RP_ID           = example.com
WEBAUTHN_ALLOWED_ORIGINS = https://app1.example.com,https://app2.example.com
```

The login page is served on the same host as the protected application. One nginx-auth instance may serve
several hosts; with a parent domain as RP ID a key registered on `app1` works on `app2`. Every origin must be
the RP ID or its subdomain. The origin of a request is found by its `Host` header in this list, so nginx must
pass the external host: `proxy_set_header Host $host:$server_port;`. Every browser POST must carry an `Origin`
header equal to that origin.

### nginx with login context and policy id

`auth_request` passes the policy id of the protected location. When access is denied, nginx-auth answers 401
with `X-Login-Context`; nginx carries it to the login page, so the policy and the return URL come from the
server, not from the URL.

```nginx
location /admin {
    auth_request      /nginx-auth-request-check;
    auth_request_set  $login_ctx $upstream_http_x_login_context;
    error_page        401 = @login;
    proxy_pass        http://backend;
}

location = /nginx-auth-request-check {
    internal;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host           $host:$server_port;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Policy-Id    "admin";   # overwrites any client value
    proxy_pass http://127.0.0.1:9091/auth/nginx-auth-request-check;
}

location @login {
    return 302 /auth?ctx=$login_ctx;
}

location /auth {
    proxy_set_header Host        $host:$server_port;
    proxy_set_header X-Real-IP   $remote_addr;
    proxy_set_header X-Policy-Id "";             # the login page carries no policy
    proxy_pass http://127.0.0.1:9091;
}
```

nginx **must** overwrite `X-Policy-Id`. When the policy file has a `locations` section, a missing or unknown
policy id in `auth_request` is answered with 403 (configuration error), never with a fallback. `none` is a
built-in id for "group policy only". The session is checked against the policy on every request, so a valid
`AUTH_TOKEN` is not enough by itself: an `LDAP_TOTP` session in a location that requires WebAuthn gets 401 and
the login page asks for the security key only (step-up, no password; a new `AUTH_TOKEN` replaces the old one).

### Policy file

`WEBAUTHN_POLICY_FILE`, JSON. Unknown keys are an error.

```json
{
  "version": 1,
  "groups": {
    "cn=admins,ou=groups,dc=example,dc=com": { "requireWebAuthn": true },
    "ops": { "requireSingleDeviceCredential": true,
             "allowedAaguids": ["cb69481e-8ff7-4039-93ec-0a2729a154a8"] }
  },
  "locations": {
    "admin": { "requireWebAuthn": true, "maxAuthAge": 900 }
  }
}
```

Group keys match a `memberOf` value as a full DN (case-insensitive) or as its leftmost `cn`. Nested groups are
not resolved; group changes apply at the next full login.

| Parameter                       | Meaning                                             | Combination of matching rules |
|---------------------------------|-----------------------------------------------------|-------------------------------|
| `requireWebAuthn`               | TOTP / password-only sessions are not accepted      | OR                            |
| `requireSingleDeviceCredential` | only keys with `BE=0` (not synced)                  | OR                            |
| `allowedAaguids`                | only keys whose declared AAGUID is listed           | intersection; empty → deny    |
| `maxAuthAge`                    | seconds since the last WebAuthn check, else step-up | minimum                       |

The last three imply `requireWebAuthn`. `allowedAaguids` filters the AAGUID the authenticator declares; without
attestation verification (not implemented) it is not proof of the key model.

### Recovery and admin CLI

A user whose policy requires WebAuthn and who has no usable key can only enroll with an enrollment secret
issued by an administrator after verifying the person over a separate trusted channel. Flow: password →
enrollment secret → register a new key → log in with it. The grant is used up when the key is saved.

The admin API listens on `127.0.0.1:WEBAUTHN_ADMIN_PORT` (separate connector, not reachable through the main
port) and requires `WEBAUTHN_ADMIN_TOKEN` (at least 32 characters; `API_CHECK_TOKENS` are not accepted).

```bash
export WEBAUTHN_ADMIN_TOKEN=...
java -jar nginx-auth.jar admin show  alice
java -jar nginx-auth.jar admin grant alice --ttl-hours 24 --uses 1
java -jar nginx-auth.jar admin reset alice --grant
```

`reset` deletes all keys (the user handle is kept), revokes the old grant, ends all sessions and pending logins
of the user and optionally issues a new grant. The secret is printed once and never stored or logged.

### Storage

`<WEBAUTHN_STORAGE_DIR>/<uid>.json`, one file per user, written atomically (temp → fsync → rename → fsync of
the directory). The directory must be `0700` and files `0600`; symlinks, malformed files and duplicate
credential IDs stop the service at startup. Only one nginx-auth process may use a directory. Sessions,
pending logins and login contexts are in memory and are lost on restart.

### Audit

Logger `nginx-auth.audit`, `event=... key=value`: registration, removal, authentication success and failure,
policy rejections, signature counter anomalies, CSRF/Origin rejections, enrollment grants, reset, step-up.
Credential IDs appear as a short hash. Keys, challenges, assertions, tokens, passwords and secrets are never
logged.

### Notes and residual risks

- The password is still typed on every login; a phishing page can capture it even though it cannot finish the login.
- Policy, credential storage and audit use the LDAP `uid`, not the typed username.
- With `OTP_ENABLED=true` a password change (`/auth/change-password`) needs the TOTP code, as before, unless
  the account (identified by the directory after the old-password bind) already has security keys. A user
  with keys and an *expired* password cannot be identified before the change and still needs the code (or an
  administrator). After the change no session is issued without the second factor the policy requires, and
  all existing sessions of the account are revoked. A login of the same account that was in progress during
  the change (even with the new password) is refused and has to be repeated.
- TOTP secrets in `OTP_SECRETS_FILE` are looked up by the exact typed username. As specified, the second factor is asked after the change, so someone
  who knows the password of a WebAuthn-only user can change it (like any LDAP client could) and lock the user
  out; they still get no session.
- With `WEBAUTHN_COUNTER_POLICY=reject` a non-increasing signature counter blocks the login.
- `/nginx-auth/api/check-*` does not do WebAuthn and does not issue sessions.

## Environment variables

| Name                       | Default value              | Description                      |
|----------------------------|----------------------------|----------------------------------|
| TOKEN_COOKIE_NAME          | AUTH_TOKEN                 |                                  |
| TOKEN_COOKIE_ASSIGNED_NAME | AUTH_TOKEN_ASSIGNED        |                                  |
| BACK_URL_NAME              | back                       |                                  |
| AUTH_URL                   | /auth                      |                                  |
| INTERNAL_PREFIX            | /internal-                 |                                  |
| X_ACCEL_REDIRECT           | X-Accel-Redirect           |                                  |
| CONNECTOR_PORT             | 9091                       | Web server port                  |
| LDAP_URL                   | ldaps://localhost:636      | LDAP server url                  |
| LDAP_USERS_DN              | ou=users,dc=example,dc=com | LDAP Users DN                    |
| OTP_ENABLED                | true                       | Enable OTP                       |
| OTP_SECRETS_FILE           | otp.properties             | TOTP secrets; reread on mtime change (at most every 5 s) |
| SECURE_COOKIE              | true                       | Enable secure cookies            |
| API_CHECK_ENABLED          | false                      | Enable /nginx-auth/api/check     |
| API_CHECK_TOKENS           |                            | Access tokens delimited by comma |
| LOGIN_MAX_FAILURES         | 2                          | Failed attempts on the username bucket before throttle |
| LOGIN_IP_MAX_FAILURES      | 20                         | Failed attempts from one IP before throttle (no delay) |
| LOGIN_DELAYS_SECONDS       | 0,2                        | Delay in seconds before the n-th credential attempt |
| LOGIN_LOCKOUT_SECONDS      | 300                        | Once throttled, at most one bind per this interval |
| LOGIN_FAILURE_WINDOW_SECONDS | 900                      | Idle TTL for a limiter bucket    |
| LOGIN_MAX_CONCURRENT_DELAYS | 32                        | Cap on requests sleeping in a delay |
| CLIENT_IP_HEADER           | X-Real-IP                  | Client IP for limiter; skipped if absent. nginx must overwrite it |
| LDAP_UID_ATTRIBUTE         | uid                        | Canonical user id read after bind |
| LDAP_DISPLAY_NAME_ATTRIBUTE | displayName               | Display name (fallback: uid)     |
| LDAP_GROUPS_ATTRIBUTE      | memberOf                   | Groups for the policy file       |
| WEBAUTHN_ENABLED           | false                      | Enable WebAuthn                  |
| WEBAUTHN_RP_ID             |                            | RP ID, e.g. `example.com`        |
| WEBAUTHN_RP_NAME           | nginx-auth                 | RP display name                  |
| WEBAUTHN_ALLOWED_ORIGINS   |                            | Comma-separated origins; each is the RP ID or its subdomain |
| WEBAUTHN_STORAGE_DIR       | ./webauthn                 | Credential directory             |
| WEBAUTHN_CHALLENGE_TTL     | 120                        | Ceremony lifetime, seconds       |
| WEBAUTHN_PREAUTH_TTL       | 300                        | How long a password check stays valid for the second step, seconds |
| WEBAUTHN_FRESH_AUTH_AGE    | 300                        | How long a key confirmation allows adding a key, seconds |
| WEBAUTHN_LOGIN_CONTEXT_TTL | 300                        | Login context lifetime, seconds  |
| WEBAUTHN_COUNTER_POLICY    | reject                     | `reject` / `warn` on signature counter anomalies |
| WEBAUTHN_POLICY_FILE       |                            | Policy by groups and `policyId`  |
| WEBAUTHN_POLICY_HEADER     | X-Policy-Id                | Header with `policyId` from nginx |
| WEBAUTHN_ADMIN_TOKEN       |                            | Admin CLI token (≥ 32 chars); enables the admin API |
| WEBAUTHN_ADMIN_PORT        | 9092                       | Admin API port on 127.0.0.1      |
| AUTH_REQUEST_USER_HEADER   | X-Auth-User                | uid on 200 from `nginx-auth-request-check`; empty: off |
| AUTH_REQUEST_GROUPS_HEADER | X-Auth-Groups              | Short group names on 200; empty: off |

Startup fails when `WEBAUTHN_ENABLED=false` but the policy file has WebAuthn requirements, when an origin is not
under the RP ID, when the policy file or the credential directory is invalid, or when
`AUTH_REQUEST_USER_HEADER` / `AUTH_REQUEST_GROUPS_HEADER` is not a valid header name.
