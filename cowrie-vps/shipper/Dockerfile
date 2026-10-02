FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN pip install --no-cache-dir requests==2.34.2

COPY cowrie_log_shipper.py .

# Unprivileged user. /state holds the resume offset; creating it here with
# the right owner means the named volume mounted there is writable.
RUN useradd --system --uid 10001 --no-create-home shipper \
 && mkdir /state && chown 10001:10001 /state
USER 10001

CMD ["python", "cowrie_log_shipper.py", "/cowrie-logs/cowrie.json"]
