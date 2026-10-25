# One image for all three services; the command picks the role:
#   producer:  serve --host 0.0.0.0 --port 8000   (API, producer intake, change detection)
#   consumer:  consumer watch
#   web:       web --host 0.0.0.0 --port 8090
#
# Builds with NO internet access. Before building:
#   - base image loaded:  docker load -i offline-bundle/images/python-3.14.7-slim-trixie.tar
#   - wheels present:     vendor/wheels/  (deploy/offline/download.sh, or by hand from
#                         deploy/offline/DOWNLOAD-LIST.md)
# Every wheel is checked against the sha256 in requirements.lock.txt.

# python:3.14.7-slim-trixie = sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d
FROM python:3.14.7-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/backend-iam \
    PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LOG_JSON=false \
    SYNC_CONFIG_PATH=/config/sync.yaml \
    PRODUCER_CONFIG_PATH=/config/producer.yaml \
    CONSUMER_CONFIG_PATH=/config/consumer.yaml

COPY requirements.lock.txt /tmp/requirements.lock.txt
COPY vendor/wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index --find-links=/tmp/wheels --require-hashes \
        -r /tmp/requirements.lock.txt \
 && rm -rf /tmp/wheels /tmp/requirements.lock.txt

RUN useradd --system --uid 10001 --user-group --home-dir /data --shell /usr/sbin/nologin iam \
 && mkdir -p /data /config \
 && chown iam:iam /data
COPY app /opt/backend-iam/app

USER 10001:10001
WORKDIR /data
ENTRYPOINT ["python", "-m", "app.cli"]
CMD ["--help"]
