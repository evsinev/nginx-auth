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
