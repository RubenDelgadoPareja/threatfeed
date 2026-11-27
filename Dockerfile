FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --frozen --no-dev

# Non-root, UID 1000 by default so it matches the usual Linux/WSL developer: the worker writes
# the shared .cache bind mount, and Beat needs a writable HOME (/tmp). Compose can override the
# UID for hosts where it differs.
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app
ENV PATH="/app/.venv/bin:$PATH" HOME=/tmp
USER app

EXPOSE 8000
CMD ["python", "-m", "threatfeed.serve"]
