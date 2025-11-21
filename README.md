nginx-auth
==========

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
        proxy_pass http://127.0.0.1:9091;
    }
    
    location /srvlog {
        proxy_set_header Host              $host:$server_port;
        proxy_set_header x-Forwarded-proto $scheme;
        proxy_pass http://127.0.0.1:9091;
    }
    
    location /internal-srvlog {
        proxy_set_header Host              $host:$server_port;
        proxy_set_header x-Forwarded-proto $scheme;
        
        internal;
        proxy_set_header nginx_location "/internal-srvlog";
        
        proxy_pass http://127.0.0.1:9091/srvlog;
    }
```

### nginx using auth_request

```nginx configuration
    location /srvlog {
        proxy_pass http://127.0.0.1:9091;

        auth_request            http://127.0.0.1:9091/nginx-auth-request-check;
        proxy_pass_request_body off;
        error_page              401 @error401;
    }
    
    location @error401 {
      # In place of a 401 error, we rewrite to a 302 that shows the login page
      return 302 https://auth.example.com/?url=$scheme://$http_host$request_uri;
    }
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
| SECURE_COOKIE              | true                       | Enable secure cookies            |
| API_CHECK_ENABLED          | false                      | Enable /nginx-auth/api/check     |
| API_CHECK_TOKENS           |                            | Access tokens delimited by comma |
