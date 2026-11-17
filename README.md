# Matarchiya backend

Rust + Actix Web + PostgreSQL (SQLx), organised as a Cargo workspace of small
crates following **Onion Architecture**. Today it contains the foundation and
one module, `auth`. Other modules are added later without touching it.

## Layout

```
backend/
├── Cargo.toml            workspace + the `matarchiya` binary
├── migrations/           all SQL migrations (SQLx), applied on startup
├── .env.example          every setting, documented
└── src/
    ├── main.rs           process entry point: load config, build, serve
    ├── base/             shared kernel: config helpers, errors, JWT claims, pool, logging
    ├── app/              composition root: AppConfig, Container (DI), routers, create_app
    └── modules/
        └── auth/         authentication module (the only one so far)
```

## Architecture

Dependencies point inward only. Inside a module:

```
  api ───────────┐
                 ├──▶ application ──▶ domain
  infrastructure ┘
```

| Layer            | Contains                                                                 | May depend on                 |
| ---------------- | ------------------------------------------------------------------------ | ----------------------------- |
| `domain`         | entities, domain errors, **repository traits**                           | nothing (no actix, no sqlx)   |
| `application`    | use cases (`AuthService`) and the **ports** they need (hasher, tokens)   | `domain`                      |
| `infrastructure` | SQLx repositories, Argon2 hasher, JWT provider (implement the traits)    | `domain`, `application`       |
| `api`            | handlers, DTOs, mappers, error→HTTP mapping, permission middleware       | `application`, `domain`       |

Only `app/src/container.rs` knows which concrete implementation backs each
trait. That is what makes `application` testable with in-memory fakes (see
`application/services/auth_tests.rs`).

Crates never depend on each other except through `base`; **`app` is the only
crate that knows every module.** Route guards (which permission a path needs)
are declared in `app/src/routers/`, not inside module crates.

## Running it

Requires Rust (edition 2024) and PostgreSQL 13+.

```sh
cd backend
cp .env.example .env          # then edit DATABASE_URL, JWT_SECRET, ...
createdb matarchiya
cargo run
```

On start-up the app applies pending migrations (a failed migration aborts
start-up) and, if `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` are set,
creates that admin account when it does not already exist. Without one, a fresh
database has nobody who can sign in.

## HTTP API

Matches what `frontend/src/services/{api,auth}.ts` already calls.
Errors are `{ "message": "...", "statusCode": 400 }`.

| Method & path        | Auth                          | Body / result |
| -------------------- | ----------------------------- | ------------- |
| `GET  /health`       | none                          | `200` |
| `POST /auth/login`   | none                          | `{ email, password }` → `{ accessToken, user: { id, name, email, role } }` + `Set-Cookie: refresh_token` |
| `POST /auth/refresh` | `refresh_token` cookie        | → `{ accessToken, user }` + a **new** cookie (the old token stops working) |
| `POST /auth/logout`  | `Bearer` token (`user` perm.) | ends this session, clears the cookie |
| `GET  /auth/me`      | `Bearer` token (`user` perm.) | → `{ id, name, email, role }` |

Notes worth knowing:

* The refresh token is **only** in an `HttpOnly` cookie, never in a JSON body.
* Wrong email/password is **400**, not 401. The frontend's axios interceptor
  treats every 401 as "access token expired" and would try a refresh and show
  the wrong error. Expired/invalid tokens on protected routes are 401.
* Cookie `Path` is `/auth` (`REFRESH_COOKIE_PATH`). If the API is mounted
  behind a prefix such as `/api`, change it to match, or the browser will never
  send the cookie. Over plain http use `REFRESH_COOKIE_SECURE=false`; the page
  and API must then be same-site (e.g. both on `localhost`).

### Security model

* Passwords: **Argon2id** (PHC string), hashed on the blocking thread pool.
  Unknown emails still cost one hash verification so timing does not reveal
  which emails exist.
* Access token: short-lived HS256 JWT (`JWT_TOKEN_EXP_MINUTES`, default 15).
* Refresh token: 256 random bits; **only its SHA-256 is stored**. Each refresh
  rotates it within the same *family* (one per login). Presenting an
  already-used token revokes the whole family, so a stolen copy dies as soon
  as either side refreshes.
* Authorization: roles → permissions in the database (`roles`, `permissions`,
  `role_permissions`). Seeded: `admin` (has `admin` + `user`) and `user`
  (`user`). Roles are checked per request against the DB; the access token's
  role is trusted only for its short lifetime.

## Migrations

* Never edit, rename or delete a migration that has been applied or merged.
  Add a new file with a new, increasing timestamp: `migrations/YYYYMMDDHHMMSS_name.sql`.
* Keep them additive and safe for production data.
* `app/build.rs` makes Cargo rebuild when the folder changes, so a new file is
  always embedded.
* Before pointing this at an existing database, make sure its
  `_sqlx_migrations` history is accurate; never "fix" a mismatch by editing old
  files.

## Tests

```sh
cargo test                     # no database needed
```

This runs the use-case tests (in-memory fakes), the JWT/Argon2/cookie/config
unit tests, and the HTTP contract tests (status codes, JSON shapes, cookies,
CORS) against a stub service.

Tests that need a real Postgres are marked `#[ignore]`. `#[sqlx::test]` creates
and drops its own throw-away database per test, so existing data is untouched:

```sh
export DATABASE_URL=postgres://user:pass@localhost:5432/postgres   # a role that can CREATE DATABASE
cargo test -- --include-ignored
```

They cover the migrations/seed data, every SQL query, the unique-email and
soft-delete rules, refresh-token rotation (including 8 concurrent rotations of
one token: exactly one wins), and the full login → refresh → replay → logout
flow over HTTP.

## Adding a module

Say `courses`:

1. `src/modules/courses/` with its own `Cargo.toml` (`name = "courses"`,
   dependencies via `workspace = true`, plus `base = { path = "../../base" }`).
   The workspace picks it up automatically (`members` includes `src/modules/*`).
2. Mirror the layering: `domain/`, `application/`, `infrastructure/`, `api/`.
   Do **not** depend on `auth`; handlers can take `base::jwt_claims::JwtClaims`
   to learn who is calling.
3. Add a new SQL file under `migrations/` for its tables.
4. In `app`: add `courses = { path = "../modules/courses" }`, a config struct
   composed into `AppConfig`, its services in `Container`, and
   `routers/courses.rs`; mount it in `create_app`. Guard routes there with
   `check_permission_middleware(req, next, "<permission>")` from the auth crate.
5. Seed any new permissions/role grants in a new migration.
