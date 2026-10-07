"""Runtime route inventory: ask FastAPI itself which routes exist and what each depends on.

Usage: route_oracle.py <backend-dir> <module:attr> <out.csv>
Imports the app (no server, no requests) and records, per route:
  - method and full path, from two independent FastAPI sources:
      (a) the route objects (APIRoute, or FastAPI >=0.141 _IncludedRouter.effective_route_contexts())
      (b) the public OpenAPI document (app.openapi())
  - the resolved dependency tree (prefixes, router-level dependencies and Annotated aliases
    resolved exactly as FastAPI resolves them)
  - the OpenAPI security requirement
Exits non-zero if (a) and (b) disagree on the (method, path) set.
"""
import csv
import importlib
import sys

backend, target, out = sys.argv[1:4]
sys.path.insert(0, backend)
from fastapi.routing import APIRoute  # noqa: E402

module_name, attr = target.split(":")
app = getattr(importlib.import_module(module_name), attr)


def tree(dependant):
    names = []
    for d in dependant.dependencies:
        fn = d.call
        names.append(getattr(fn, "__qualname__", None) or type(fn).__name__)
        names.extend(tree(d))
    return list(dict.fromkeys(names))


def contexts(routes):
    for r in routes:
        if isinstance(r, APIRoute):
            yield r.path, r.methods, r.dependant, r.endpoint
        elif hasattr(r, "effective_route_contexts"):  # FastAPI >= 0.141
            for c in r.effective_route_contexts():
                yield c.path, c.methods, c.dependant, c.endpoint


rows, seen = [], set()
for path, methods, dependant, endpoint in contexts(app.routes):
    for m in sorted(set(methods) - {"HEAD", "OPTIONS"}):
        seen.add((m, path))
        rows.append({"method": m, "path": path,
                     "endpoint": f"{endpoint.__module__}.{endpoint.__qualname__}",
                     "dependency_tree": " > ".join(tree(dependant))})

spec = app.openapi()
openapi = {}
for path, ops in spec.get("paths", {}).items():
    for m, op in ops.items():
        if m.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            openapi[(m.upper(), path)] = ",".join(sorted(k for s in op.get("security", []) for k in s)) or "none"
for r in rows:
    r["openapi_security"] = openapi.get((r["method"], r["path"]), "MISSING")

rows.sort(key=lambda x: (x["path"], x["method"]))
with open(out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
only_routes, only_openapi = seen - set(openapi), set(openapi) - seen
print(f"{len(rows)} routes -> {out}; route objects vs OpenAPI: "
      f"{'AGREE' if not (only_routes or only_openapi) else f'DISAGREE {only_routes} {only_openapi}'}")
sys.exit(1 if only_routes or only_openapi else 0)
