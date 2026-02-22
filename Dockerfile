FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY clownpeanuts /app/clownpeanuts
RUN pip install --no-cache-dir .[api]
RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup appuser \
    && chown -R appuser:appgroup /app

USER appuser

CMD ["clownpeanuts", "status", "--config", "/app/clownpeanuts/config/defaults.yml"]
