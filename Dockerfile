# Cloud Run image (course Day-5 convention: python:3.12-slim + uv + uvicorn).
FROM python:3.12-slim

# uv for fast, reproducible installs.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
# pyproject.toml references README.md as the package long-description; copy
# it before `uv pip install -e .` so hatchling's editable build doesn't fail.
COPY pyproject.toml README.md ./
COPY src ./src
COPY app ./app
COPY corpus ./corpus

# Core is dependency-free; install the agent extra for the served gateway shell.
RUN uv pip install --system -e ".[agent]"

ENV PORT=8080
# OTEL content capture disabled by default — a security tool must never log raw payloads.
ENV OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=NO_CONTENT

EXPOSE 8080
CMD ["uvicorn", "app.fast_api_app:app", "--host", "0.0.0.0", "--port", "8080"]
