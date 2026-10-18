FROM dvaia-owned-http-service:20260919 AS builder
USER root
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev
COPY namespace-init.c /tmp/shadow-init.c
RUN gcc -O2 -Wall -Wextra -Werror /tmp/shadow-init.c -o /tmp/dvaia-owned-shadow-init
FROM dvaia-owned-http-service:20260919
USER root
COPY --from=builder /tmp/dvaia-owned-shadow-init /usr/local/libexec/dvaia-owned-shadow-init
RUN cp /usr/local/libexec/dvaia-owned-http-supervisor /usr/local/libexec/dvaia-owned-shadow-supervisor
COPY worker.bundle.js /usr/local/libexec/dvaia-owned-shadow-worker.js
COPY network-manifest.json /usr/local/libexec/dvaia-owned-shadow-manifest.json
COPY executor.js contract.js operationStore.js service.js buildAssets.js /app/owned-shadow/
RUN node /app/owned-shadow/buildAssets.js
USER 10001:10001
