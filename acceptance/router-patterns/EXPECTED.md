# Fixture: router-patterns (independent of the template)

Written for authcheck M1a discovery acceptance so discovery is not tuned to one project.
Ground truth comes from FastAPI itself (`route_oracle.py`): route objects and the OpenAPI document,
which agree, and which are identical under FastAPI 0.115.0 and 0.141.1.

- `ENABLE_DEBUG` unset: 11 mounted (method, path) pairs. `ENABLE_DEBUG=1`: 12 (adds P12).
- `expected-inventory.csv` lists every case with the runtime truth and the static handling M1a must show.
- Pass = every mounted pair either discovered with the correct effective method and full path, or
  explicitly reported unresolved with the stated reason (P09 decorator, P10/P11); P12 marked
  conditional; P13 absent from mounted endpoints; no invented routes or paths.
- Dependency references are references only: P04/P05 link to `get_db`, which is not authentication.
