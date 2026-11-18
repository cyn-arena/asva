# ASVA build of PyGoat. Upstream's original Dockerfile no longer builds (its Python 3.11 beta
# Buster base image and pinned Debian packages are gone), so ASVA customises this file in place,
# as with NodeGoat; see ASVA_IMPORT.md. The scan, PR checks, candidate rescans and the
# Kubernetes deploy all build this one file.
FROM python:3.11-slim-trixie

WORKDIR /app

# Compile older Python dependencies against the base image's Python headers.
RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential dnsutils libpq-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=pygoat.asva_settings

# Upstream's pip and package pins, so the vulnerable baseline stays the same.
RUN python -m pip install --no-cache-dir pip==22.0.4
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# The app runs as user 1000 (compose.asva.yml and the Kubernetes pod set it). At runtime it
# creates app.log in /app and lab files under /app, and keeps SQLite in /data, so user 1000
# owns /app, everything in it, and /data.
COPY --chown=1000:1000 . /app/
RUN chown 1000:1000 /app && mkdir -p /data && chown 1000:1000 /data
EXPOSE 8000

RUN python3 /app/manage.py collectstatic --noinput

# asva/start.py migrates and loads the challenges on every start, then runs CMD.
ENTRYPOINT ["python", "/app/asva/start.py"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "6", "pygoat.wsgi"]
