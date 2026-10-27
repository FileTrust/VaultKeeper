FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates bash util-linux passwd \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/filetrust-vaultkeeper
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv .venv \
    && for attempt in 1 2 3; do \
         .venv/bin/python -m pip install --timeout 120 --retries 5 -r requirements.txt && break; \
         if [ "$attempt" -eq 3 ]; then exit 1; fi; \
         echo "Python dependency installation interrupted; retrying ($attempt/3)..."; \
         sleep 2; \
       done \
    && .venv/bin/python -m pip check
ENV PATH="/opt/filetrust-vaultkeeper/.venv/bin:${PATH}"

FROM base AS build
COPY core/go_build.py core/vk_connect.py ./core/
COPY runtime ./runtime
RUN python -c "import sys; sys.path.insert(0,'core'); from go_build import build_runtime; build_runtime('.')" \
    && rm -rf .build-cache

FROM base AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends procps && rm -rf /var/lib/apt/lists/*
COPY . ./
COPY --from=build /opt/filetrust-vaultkeeper/bin ./bin
RUN groupadd --gid 10001 ftvaultkeeper \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/filetrust-vaultkeeper --no-create-home --shell /usr/sbin/nologin ftvaultkeeper \
    && mkdir -p /var/lib/filetrust-vaultkeeper /etc/filetrust-vaultkeeper /run/filetrust-vaultkeeper .filetrust-updates \
    && chown 10001:10001 /var/lib/filetrust-vaultkeeper /etc/filetrust-vaultkeeper /run/filetrust-vaultkeeper \
    && chmod 0700 /var/lib/filetrust-vaultkeeper /etc/filetrust-vaultkeeper /run/filetrust-vaultkeeper
ENV HOME=/var/lib/filetrust-vaultkeeper RUNTIME_DIRECTORY=/run/filetrust-vaultkeeper TMPDIR=/run/filetrust-vaultkeeper FILETRUST_CONTAINER=1
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "/opt/filetrust-vaultkeeper/core/container_cli.py"]
CMD ["run"]
