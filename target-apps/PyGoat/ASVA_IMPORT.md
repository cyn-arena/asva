# PyGoat source import and container review

## Source provenance

- Upstream: https://github.com/adeyosemanputra/pygoat
- Revision: `19d17cc8874861142b330636d068bbde54e86b85` (master at import)
- Imported on: 8 October 2026
- Method: GitHub source ZIP at the exact revision, copied into `target-apps/PyGoat` without a nested Git repository.
- Archive SHA256: `11f706c90eb870187e496e8c2ecd5757a78fb1ccace9580cc95e57ecef8fb110`
- Licence: MIT; see the preserved `LICENSE.md`.
- Upstream files were imported unchanged. This note is an ASVA addition.

This is an intentionally vulnerable target for ASVA deployment and remediation experiments. The initial milestone is to deploy the unchanged source locally; no LLM, Azure or Kubernetes access is needed for that milestone.

## Existing container setup

| File | Role |
| --- | --- |
| `Dockerfile` | Builds the Django application image, installs requirements, performs migrations at build time, and starts Gunicorn on container port 8000. |
| `docker-compose.yml` | Builds the web image locally and starts a separate migration container from `pygoat/pygoat:latest`. Both containers mount the checkout at `/app`. |
| `requirements.txt` | Pins application dependencies, including Django, Gunicorn and PostgreSQL-related packages. |
| `pygoat/settings.py` | Defaults to SQLite at `/app/db.sqlite3`; calls `django_heroku.settings`, which can modify settings depending on the environment. |
| `challenge/management/commands/populate_challenges.py` | Provides `manage.py populate_challenges` to load challenge definitions after database setup. |

NodeGoat's MongoDB setup should not be copied into PyGoat. The default PyGoat configuration uses SQLite, despite including PostgreSQL libraries.

## Findings before the first build

1. **Base image and package compatibility:** the Dockerfile uses `python:3.11.0b1-buster` and exact Debian package versions. The first user-run build failed at `apt-get update`: Buster Release URLs returned HTTP 404. Python dependency installation and application startup have not yet been tested.
2. **Database lifecycle:** migrations run inside the Dockerfile. Compose subsequently mounts the checkout over `/app`, hiding the image's application files and any database created there. Its separate migration service creates the host-side database instead. A future image-only deployment needs an explicit runtime database initialization and persistence strategy.
3. **Different migration environment:** the web service builds from this snapshot, while the migration service uses an unpinned published `latest` image. The dependency environments may differ even though both mount the same source. Prefer the same locally built image for both when preparing the ASVA deployment configuration.
4. **Migration ordering:** the short `depends_on` form orders startup but does not wait for successful migration completion. A repeatable configuration should wait for the migration service to complete successfully before starting the web service.
5. **Image validation:** source bind mounts make the upstream Compose setup useful for development, but do not prove that the built image contains the intended source and works independently. Include an image-only check in the deployment milestone.
6. **Local port binding:** `8000:8000` publishes on all host interfaces by default. The local ASVA configuration should bind `127.0.0.1:8000:8000` for this deliberately vulnerable target.
7. **Build context:** there is no upstream `.dockerignore`. Before building, add a target-specific one to omit local environments, databases, scan outputs and other generated files while retaining application assets.
8. **Readiness and functionality:** no health check is defined. Check HTTP startup, a login page and a representative interaction. Verify static assets and challenge data; a running Gunicorn process alone is insufficient.

These are deployment observations, not remediation results. Preserve the vulnerable baseline and document any container compatibility changes separately from security fixes.

## Verification at initial import

- Compared every imported upstream file with the extracted pinned archive using SHA256.
- Confirmed no nested `.git` directory or file was imported.
- Confirmed Docker and Docker Compose CLIs are available.
- `docker compose -f target-apps/PyGoat/docker-compose.yml config --quiet` passed from the ASVA repository root. This validates configuration parsing only.
- No dependencies were installed, image built, containers started, scanners run or LLM called.

## Next deployment check

`Dockerfile.asva` is an ASVA compatibility variant using `python:3.11-slim-bookworm` and release-compatible OS build packages. It retains upstream Python dependency pins and build-time migration behavior so subsequent failures can be diagnosed separately. The original `Dockerfile` is unchanged. From `target-apps/PyGoat`, retry with:

```powershell
docker build --progress=plain -f Dockerfile.asva -t asva-pygoat:baseline .
```

The first compatibility image built and ran successfully in the user's local test. Registration, login, logout, lab navigation and restart persistence were checked manually. The ASVA configuration has since moved migrations to runtime and added a SQLite volume, readiness and CI validation; see `docs/pygoat.md` at the ASVA repository root. Use `compose.asva.yml` for that configuration. The upstream `docker-compose.yml` still selects the original Dockerfile.

## Single Dockerfile (11 November 2026)

`Dockerfile.asva` has been folded into `Dockerfile`, which ASVA now customises in place, as with NodeGoat. The scan, PR checks, candidate rescans and the Kubernetes deploy all build that one file, so the deployed image is the one ASVA checked. The original upstream file is recoverable from the archive recorded under Source provenance. The app runs as user 1000 (set by `compose.asva.yml` and the Kubernetes pod), so the image gives that user `/app`, its contents and `/data`: at runtime PyGoat creates `app.log` in `/app` and lab files under it. The sections above describe the state at import.

Prepare a minimal ASVA local container configuration addressing the findings above, then build from this imported source and verify startup, migrations, functional checks and cleanup. Record the tested source revision and image identity. Do not treat a pulled upstream image as evidence that this checkout builds.

## References

- [Upstream source at the imported revision](https://github.com/adeyosemanputra/pygoat/tree/19d17cc8874861142b330636d068bbde54e86b85)
- [Compose startup ordering](https://docs.docker.com/compose/how-tos/startup-order/)
- [Docker bind mount behavior](https://docs.docker.com/engine/storage/bind-mounts/)
