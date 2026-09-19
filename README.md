# Spring Boot OAuth2 Demo

[![Java CI with Maven](https://github.com/hendisantika/spring-boot-oauth2-demo/actions/workflows/maven.yml/badge.svg)](https://github.com/hendisantika/spring-boot-oauth2-demo/actions/workflows/maven.yml)

A small OAuth2 playground built on **Java 25**, **Spring Boot 4.1.1** and **Spring Security 7.1.1**.
One application plays three roles at once:

- an **authorization server** that issues signed JWT access tokens,
- a **resource server** that accepts those tokens on `/resources/**`,
- a plain **HTTP Basic** front door for the same endpoints, so you can poke at them without a token.

## Requirements

- JDK 25
- Maven 3.9+ (or just use the bundled `./mvnw`)

## Run it

```bash
./mvnw spring-boot:run
```

The app starts on <http://localhost:8080>.

## Users

| Username     | Password   | Role         |
|--------------|------------|--------------|
| `user`       | `password` | `ROLE_USER`  |
| `app_client` | `nopass`   | `ROLE_USER`  |
| `admin`      | `password` | `ROLE_ADMIN` |

## Registered clients

| Client ID     | Secret   | Grant types                        | Scopes         | Role in issued tokens |
|---------------|----------|------------------------------------|----------------|-----------------------|
| `normal-app`  | *(none)* | `authorization_code` (PKCE), `refresh_token` | `read`, `write` | `ROLE_CLIENT`         |
| `trusted-app` | `secret` | `client_credentials`               | `read`, `write` | `ROLE_TRUSTED_CLIENT` |

`normal-app` is a **public** client: it has no secret and must use PKCE. Its redirect URI is
`http://127.0.0.1:8080/login/oauth2/code/normal-app`.

## Endpoints

Authorization server (standard Spring Authorization Server paths):

| Path                                       | Purpose                       |
|--------------------------------------------|-------------------------------|
| `/.well-known/oauth-authorization-server`  | discovery metadata            |
| `/oauth2/authorize`                        | authorization endpoint        |
| `/oauth2/token`                            | token endpoint                |
| `/oauth2/jwks`                             | public keys for verification  |
| `/oauth2/revoke`, `/oauth2/introspect`     | revocation and introspection  |

Protected application resources — each accepts **either** HTTP Basic **or** a bearer JWT:

| Path                          | Required role         |
|-------------------------------|-----------------------|
| `/resources/user`             | `ROLE_USER`           |
| `/resources/admin`            | `ROLE_ADMIN`          |
| `/resources/client`           | `ROLE_CLIENT`         |
| `/resources/trusted_client`   | `ROLE_TRUSTED_CLIENT` |
| `/resources/principal`        | any authenticated     |
| `/resources/roles`            | any authenticated     |

## Try it

### HTTP Basic

```bash
curl -u user:password  http://localhost:8080/resources/user    # hello user
curl -u admin:password http://localhost:8080/resources/admin   # hello admin
curl -u user:password  http://localhost:8080/resources/admin   # 403, wrong role
```

### Client credentials

```bash
TOKEN=$(curl -s -u trusted-app:secret \
  -d grant_type=client_credentials -d 'scope=read write' \
  http://localhost:8080/oauth2/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/resources/trusted_client
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/resources/roles
```

### Authorization code with PKCE

Open this in a browser, sign in as `user` / `password`, and approve the consent screen:

```
http://localhost:8080/oauth2/authorize
  ?response_type=code
  &client_id=normal-app
  &scope=read%20write
  &redirect_uri=http://127.0.0.1:8080/login/oauth2/code/normal-app
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

Then swap the `code` from the redirect for a token:

```bash
curl -s -d grant_type=authorization_code \
     -d code=THE_CODE \
     -d client_id=normal-app \
     -d redirect_uri=http://127.0.0.1:8080/login/oauth2/code/normal-app \
     -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk \
     http://localhost:8080/oauth2/token
```

## How roles travel in the token

A bearer token normally carries only `SCOPE_*` authorities, which would leave the
`@PreAuthorize("hasRole(...)")` checks unreachable. So the authorization server writes a custom
`roles` claim — the end user's roles, or the client's role for `client_credentials` — and the
resource server converts it back into `ROLE_*` authorities alongside the usual scopes. The result
is that the same rules apply whether a caller arrives with Basic credentials or a JWT.

## Configuration

| Property                        | Default                    | Meaning                             |
|---------------------------------|----------------------------|-------------------------------------|
| `resource.id`                   | `spring-boot-application`  | audience (`aud`) stamped on tokens  |
| `access_token.validity_period`  | `3600`                     | access token lifetime, in seconds   |

## Build and test

```bash
./mvnw clean package
```

## Notes

This is a demo, not a template for production:

- users, clients and authorizations are all **in memory** and vanish on restart;
- the RSA signing key is **generated fresh at every start-up**, so tokens do not survive a restart;
- passwords and the client secret are literals in the source.

It was originally written against the long-retired `spring-security-oauth2` project. That library,
along with the `implicit` and `password` grants it offered, is gone — this version is rebuilt on
Spring Authorization Server, which is part of Spring Security itself as of 7.x. `normal-app` uses
`authorization_code` + PKCE in place of `implicit`, and `trusted-app` is `client_credentials` only
in place of `password`.
