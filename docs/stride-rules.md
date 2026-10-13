# STRIDE threat analysis (V0.5)

This document describes the deterministic STRIDE analysis added in V0.5. It is generated from, and kept consistent with, the rule catalog in `src/stride/strideRules.ts` (a test fails if a rule or a recognised control library is missing here).

## What the analysis is, and is not

- It reads **only the V0.4 architecture model**: components, declaration relationships, evidence and recorded uncertainty. It makes no network request, calls no LLM, and never reads or runs the analysed project beyond what V0.2–V0.4 already extracted.
- Every result is a **candidate threat for human review**. It is **not** a confirmed vulnerability, and it is not prioritised, scored or matched to CVEs (those are later milestones).
- The model contains **no data flows, no trust boundaries, no authentication/TLS/secrets configuration and no source code behaviour**. None of these are invented. Where a rule would need them, the threat states the assumption explicitly, or the rule reports "not assessed".

## Reading a threat

Each threat has:

| Field | Meaning |
|---|---|
| `id` | `threat:<ruleId>\|<targetId>` plus an optional `\|<qualifier>` (for example the manifest file). Stable for identical input. |
| `category` | One of Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. |
| `basis` | `observed`: the triggering condition is itself a declared fact. `assumption-dependent`: applicability rests on stated assumptions. |
| `target` | The affected component, or relationship (a client-library link), as an id of the V0.4 model. |
| `observations` | Facts taken from the model, each with its evidence (source file, rule, explanation). |
| `assumptions` | What would have to be true for the threat to apply. **Not established by the model.** |
| `limitations` | What this analysis cannot see. Never empty. |

Output is sorted by STRIDE category, then rule id, then threat id, and does not depend on the order of the model or on where the project is located.

## Rule catalog (15 rules)

| Rule | STRIDE | Basis | Fires when | Reported "not assessed" when | Key assumptions |
|---|---|---|---|---|---|
| `STRIDE-S-001` | Spoofing | assumption-dependent | A Backend whose module declares no recognised authentication library (not assessed for Django and Hapi). | Django and Hapi (built-in facilities); a Backend with no containing module or no identifying framework in the model | The backend is reachable by callers that are not fully trusted; authentication is not implemented elsewhere |
| `STRIDE-S-002` | Spoofing | assumption-dependent | An External Service component inferred from a declared SDK/client dependency. | — | The service is reached over a network; server identity is not verified |
| `STRIDE-T-001` | Tampering | observed | A Dockerfile base image or compose service image has no tag or uses the tag "latest" (not for digest-pinned or variable references). | The image reference uses a variable | — (observed condition) |
| `STRIDE-T-002` | Tampering | observed | A Node.js, Python or Rust manifest declares dependencies with no version constraint ("*", "latest", empty, or none). Java and Go are not assessed. | — (Java and Go are outside the rule, see below) | — (observed condition) |
| `STRIDE-T-003` | Tampering | observed | A manifest declares dependencies fetched from git or URL sources that are not visibly pinned to a full commit (Node.js, Python, Rust). | — | — (observed condition) |
| `STRIDE-T-004` | Tampering | assumption-dependent | A Database component (inferred from a client library or declared as a compose database service). | — | The data store holds data whose integrity matters; writes are not restricted |
| `STRIDE-R-001` | Repudiation | assumption-dependent | A Node.js or Rust Backend whose module declares no recognised logging library. Python, Java and Go are not assessed. | Python, Java and Go backends (standard-library logging); a Backend with no module or framework | Security-relevant actions occur; no other audit trail exists |
| `STRIDE-R-002` | Repudiation | assumption-dependent | A Database component (inferred from a client library or declared as a compose database service). | — | More than one principal changes the data; no auditing exists |
| `STRIDE-I-001` | Information Disclosure | assumption-dependent | A Database component (inferred from a client library or declared as a compose database service). | — | The data store holds sensitive data; access control and encryption at rest are not enforced |
| `STRIDE-I-002` | Information Disclosure | assumption-dependent | A client-library-for relationship to a Database or External Service. | A relationship endpoint missing from the model | The library is used over a network; transport is not protected |
| `STRIDE-I-003` | Information Disclosure | assumption-dependent | An External Service component inferred from a declared SDK/client dependency. | — | The SDK needs credentials; they are not managed by a secrets facility |
| `STRIDE-D-001` | Denial of Service | assumption-dependent | A Backend whose module declares no recognised rate-limiting library. | A Backend with no module or framework | The backend is reachable by untrusted clients; no rate limiting elsewhere |
| `STRIDE-D-002` | Denial of Service | assumption-dependent | A client-library-for relationship to a Database or External Service. | A relationship endpoint missing from the model | The application depends on the target; no timeouts, retries or fallbacks |
| `STRIDE-E-001` | Elevation of Privilege | assumption-dependent | A Backend whose module declares no recognised authorization library (not assessed for Django and Hapi). | Django and Hapi (built-in facilities); a Backend with no module or framework | More than one privilege level exists; access checks are not made elsewhere |
| `STRIDE-E-002` | Elevation of Privilege | assumption-dependent | A client-library-for relationship to a Database component. | A relationship endpoint missing from the model | The application connects with a database account that is over-privileged |

Notes on exclusions (deliberate, to avoid unsupported claims):

- **STRIDE-T-002** covers Node.js, Python and Rust only. In Java a missing version usually means it is managed by a parent or BOM, and Go always records versions. Path, git, URL and workspace dependencies are excluded (T-003 covers git/URL).
- **STRIDE-T-003** does not fire when a git dependency is visibly pinned to a full 40-character commit, nor for `file:`, `link:`, `workspace:` or `npm:` alias specifiers.
- **STRIDE-T-001** does not fire for explicit version tags or digest-pinned references (a digest wins over a `latest` tag). A Dockerfile base image is a **build-time** image and is never described as a running service.
- Control-library rules count only **runtime** categories of the **same module**. A recognised library declared only as a dev or peer dependency is disclosed in the observations but not counted.
- **Frontend** components receive no rules: threats such as client-side injection need source analysis.

## Recognised control libraries

The control-absence rules (S-001, R-001, D-001, E-001) look for a finite, curated list of libraries in the module's declared runtime dependencies. A library that is not listed is not recognised, and a listed library does not prove the control is applied correctly. Names are matched after normalisation (lower-case; Python also folds `_` and `.` to `-`). An entry marked `(prefix)` matches any name that starts with it; all others must match exactly.

Frameworks with built-in access-control facilities (rules report "not assessed" instead of a threat for S-001 and E-001): Django, Hapi.

Logging is assessed only for ecosystems without a standard-library logging facility (Node.js and Rust).

### authentication

- **Node.js**: `passport`, `jsonwebtoken`, `jose`, `express-session`, `cookie-session`, `next-auth`, `express-jwt`, `koa-passport`, `koa-jwt`, `openid-client`, `express-openid-connect`, `keycloak-connect`, `oidc-provider`, `@nestjs/passport`, `@nestjs/jwt`, `@fastify/jwt`, `@fastify/auth`, `@fastify/passport`, `@fastify/session`, `@hapi/jwt`, `@hapi/basic`, `passport-…` (prefix), `@auth0/…` (prefix), `@clerk/…` (prefix), `@okta/…` (prefix), `@auth/…` (prefix)
- **Python**: `flask-login`, `flask-jwt-extended`, `flask-security`, `flask-security-too`, `flask-httpauth`, `flask-oidc`, `authlib`, `django-allauth`, `django-oauth-toolkit`, `djangorestframework-simplejwt`, `social-auth-app-django`, `fastapi-users`, `fastapi-jwt-auth`, `python-jose`, `pyjwt`, `oauthlib`
- **Java**: `com.auth0:java-jwt`, `org.springframework.boot:spring-boot-starter-security…` (prefix), `org.springframework.security:…` (prefix), `org.pac4j:…` (prefix), `io.jsonwebtoken:…` (prefix), `org.keycloak:…` (prefix), `org.apache.shiro:…` (prefix), `io.micronaut.security:…` (prefix), `io.quarkus:quarkus-security…` (prefix), `io.quarkus:quarkus-oidc…` (prefix)
- **Go**: `github.com/golang-jwt/jwt…` (prefix), `github.com/dgrijalva/jwt-go…` (prefix), `github.com/coreos/go-oidc…` (prefix), `github.com/markbates/goth…` (prefix), `github.com/gorilla/sessions…` (prefix), `golang.org/x/oauth2…` (prefix)
- **Rust**: `jsonwebtoken`, `oauth2`, `openidconnect`, `actix-identity`, `actix-session`, `actix-web-httpauth`, `axum-login`, `tower-sessions`

### authorization

- **Node.js**: `casbin`, `node-casbin`, `@casl/ability`, `@nestjs/casl`, `accesscontrol`, `role-acl`, `express-jwt-authz`, `keycloak-connect`, `oso`
- **Python**: `django-guardian`, `django-rules`, `rules`, `casbin`, `pycasbin`, `flask-principal`, `flask-security`, `flask-security-too`, `oso`, `fastapi-permissions`, `django-role-permissions`
- **Java**: `org.springframework.boot:spring-boot-starter-security…` (prefix), `org.springframework.security:…` (prefix), `org.apache.shiro:…` (prefix), `org.casbin:…` (prefix), `org.keycloak:…` (prefix)
- **Go**: `github.com/casbin/casbin…` (prefix), `github.com/open-policy-agent/opa…` (prefix), `github.com/mikespook/gorbac…` (prefix)
- **Rust**: `casbin`, `oso`, `actix-casbin…` (prefix)

### logging

- **Node.js**: `winston`, `pino`, `pino-http`, `bunyan`, `log4js`, `morgan`, `express-winston`, `roarr`, `tslog`
- **Rust**: `log`, `tracing`, `tracing-subscriber`, `env_logger`, `slog`, `fern`, `simplelog`, `flexi_logger`

### rate-limiting

- **Node.js**: `express-rate-limit`, `rate-limiter-flexible`, `@fastify/rate-limit`, `koa-ratelimit`, `koa2-ratelimit`, `@nestjs/throttler`, `express-slow-down`, `hapi-rate-limit`, `limiter`
- **Python**: `flask-limiter`, `slowapi`, `django-ratelimit`, `fastapi-limiter`, `limits`, `ratelimit`
- **Java**: `com.github.vladimir-bukhtoyarov:bucket4j`, `com.bucket4j:…` (prefix), `com.giffing.bucket4j.spring.boot.starter:…` (prefix), `io.github.resilience4j:…` (prefix)
- **Go**: `github.com/ulule/limiter…` (prefix), `golang.org/x/time…` (prefix), `github.com/didip/tollbooth…` (prefix), `github.com/juju/ratelimit…` (prefix)
- **Rust**: `governor`, `tower_governor`, `tower-governor`, `actix-governor`, `axum-governor`, `actix-limitation`

## Limitations that apply to every project

- The architecture model establishes no data flows and no trust boundaries; none are assumed or inferred.
- Authentication, authorization, TLS and secrets configuration are not read, so their presence or absence is not known.
- Compose ports, container user, privileged mode, volumes and environment, and Dockerfile USER, are not extracted by the earlier milestones and are not assessed.
- Source code is not analysed; controls implemented in code, middleware or infrastructure are not visible.
- A declared library is not evidence that it is used, or used correctly; a missing library is not evidence that a control is missing.
- Lockfiles are not read, so resolved dependency versions are not known.
- Frontend-specific threats (for example client-side injection) need source analysis and are not assessed.
- Results are candidates for review. They are not confirmed vulnerabilities and are not prioritised or scored.

## Extending the rules

1. Add a `StrideRule` to `STRIDE_RULES` in `src/stride/strideRules.ts`. A rule is a pure function of the read-only model context; it must not read files or use the network.
2. A threat must carry at least one evidenced observation and one limitation, and an `assumption-dependent` threat must state its assumptions. The engine drops (and warns about) any threat that does not, or that refers to an element missing from the model.
3. Use conditional wording ("if", "could", "may") for anything the model does not establish. Never state that a vulnerability exists.
4. Add the rule to this document (the documentation test checks it) and add positive and negative tests.

## Out of scope for V0.5

Risk scoring or prioritisation, CVE/NVD lookup, explanation or recommendation text from an LLM, mitigations, dashboards and reports.
