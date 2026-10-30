FROM owasp-ai-goat-owned-http-service:20260919 AS builder
USER root
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev
COPY namespace-init.c /tmp/shadow-init.c
RUN gcc -O2 -Wall -Wextra -Werror /tmp/shadow-init.c -o /tmp/owasp-ai-goat-owned-shadow-init
FROM owasp-ai-goat-owned-http-service:20260919
USER root
COPY --from=builder /tmp/owasp-ai-goat-owned-shadow-init /usr/local/libexec/owasp-ai-goat-owned-shadow-init
RUN cp /usr/local/libexec/owasp-ai-goat-owned-http-supervisor /usr/local/libexec/owasp-ai-goat-owned-shadow-supervisor
COPY worker.bundle.js /usr/local/libexec/owasp-ai-goat-owned-shadow-worker.js
COPY network-manifest.json /usr/local/libexec/owasp-ai-goat-owned-shadow-manifest.json
COPY executor.js contract.js operationStore.js service.js buildAssets.js /app/owned-shadow/
RUN node /app/owned-shadow/buildAssets.js
USER 10001:10001
