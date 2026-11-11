FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    HOST=0.0.0.0 \
    PORT=8788

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app ./app
COPY demo_client ./demo_client
COPY migrations ./migrations

ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8788
CMD ["python", "-m", "app.main"]
