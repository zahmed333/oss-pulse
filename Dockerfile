FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    OSS_PULSE_DATA_DIR=/data DAGSTER_HOME=/opt/dagster
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[orchestration,dashboard]"

COPY . .
RUN pip install --no-deps . && mkdir -p /data $DAGSTER_HOME

VOLUME ["/data"]
EXPOSE 3000 8501
# Default: offline demo. Override, e.g. `docker run ... dagster dev -h 0.0.0.0 -p 3000`
CMD ["oss-pulse", "demo"]
