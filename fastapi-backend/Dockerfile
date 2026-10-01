FROM python:3.12-slim

# Don't write .pyc files; flush logs immediately.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only the application code - .dockerignore keeps .env and other local
# files out of the image.
COPY app ./app
COPY scripts ./scripts

# Run as an unprivileged user, never root.
RUN useradd --system --uid 10001 --no-create-home appuser
USER 10001

EXPOSE 8000

# --proxy-headers is deliberately NOT used: X-Forwarded-For handling is done
# in app/limiter.py via TRUSTED_PROXY_HOPS so spoofed headers are ignored.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
