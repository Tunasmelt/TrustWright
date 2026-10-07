# Fixture: fastapi-template (pinned snapshot)

- **Source:** https://github.com/fastapi/full-stack-fastapi-template
- **Commit:** `f27b4721507824e57ebd0286ff1a84d82e83bf59` (committed 2026-10-07)
- **License:** MIT, Copyright (c) 2019 Sebastián Ramírez. `LICENSE` is included unchanged and must stay with this fixture.
- **Trimmed to:** root `pyproject.toml` and `uv.lock`, `backend/pyproject.toml`, and the 19 Python files under
  `backend/app/` excluding `backend/app/alembic/`. File hashes are in `SHA256SUMS`.
- **Deliberately omitted:** the repository's committed `.env`, which holds placeholder credentials. It also sets
  `FASTAPI_ENV=development`, which mounts `private.router`; that condition is recorded in `expected-inventory.csv`
  (`mounted_when`) instead.

## Inventory and how it was checked

`expected-inventory.csv`: 23 (method, path) pairs, 22 in production plus 1 dev-only. Three sources agree on 23/23:
1. a static reading of the route files (`protection_as_written`, `dependency_as_written`);
2. FastAPI's own resolved route table and dependency trees (`runtime_dependency_tree`), FastAPI 0.141.1 from `uv.lock`;
3. FastAPI's OpenAPI document (`openapi_security`).

Categories: 11 `authenticated` (via `get_current_user`), 6 `role(superuser)` (via `get_current_active_superuser`), 6 `public`.

## Cases the static analysis must handle explicitly

| Case | Where | Expected M1a handling |
|---|---|---|
| Prefix from settings | `app.include_router(api_router, prefix=settings.API_V1_STR)`; default `"/api/v1"` in `core/config.py` | Resolve to the class-attribute default **and** say it is a default an environment variable can override; or report `unresolved_prefix` and match on router-local paths. Never silently drop it. |
| Conditional router | `if settings.FASTAPI_ENV == "development": api_router.include_router(private.router)` | Discover `POST /api/v1/private/users/` and mark it conditional, not always mounted |
| Imported `Annotated` alias | `CurrentUser = Annotated[User, Depends(get_current_user)]` in `api/deps.py`, used in 3 route files (`items.py`, `login.py`, `users.py`) | Resolve to `get_current_user` (12 endpoints use it) |
| Decorator dependencies | `dependencies=[Depends(get_current_active_superuser)]` | Resolve (6 endpoints) |
| Python 3.14 syntax | `except InvalidTokenError, ValidationError:` (PEP 758) in `api/deps.py` | On an older interpreter, report `source_parse_error` for that file with the interpreter version; on 3.14, parse it |
| `app.frontend("/", ...)` | `main.py` | Not an API route; must not be reported as one |
