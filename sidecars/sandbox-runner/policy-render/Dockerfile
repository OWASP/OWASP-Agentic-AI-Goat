FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1 AS policy-helper-builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY policy-render/process-supervisor.c policy-render/policy-init.c /build/
RUN mkdir -p /out \
    && gcc -static -O2 -Wall -Wextra -Werror /build/process-supervisor.c -o /out/owasp-ai-goat-policy-render-supervisor \
    && gcc -static -O2 -Wall -Wextra -Werror /build/policy-init.c -o /out/owasp-ai-goat-policy-render-init \
    && chmod 0555 /out/owasp-ai-goat-policy-render-supervisor /out/owasp-ai-goat-policy-render-init

FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1

# Only the strict policy renderer is present. The ordinary sandbox runner and
# its mutable lesson filesystem are deliberately outside this image.
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY policy-render/listener.js policy-render/executor.js policy-render/http-handler.js policy-render/worker.js ./policy-render/
COPY policy-render/assets ./policy-render/assets
COPY policy-render/secureshopPromptPolicyContract.js /server/services/secureshopPromptPolicyContract.js
COPY --from=policy-helper-builder /out/owasp-ai-goat-policy-render-supervisor /usr/local/libexec/owasp-ai-goat-policy-render-supervisor
COPY --from=policy-helper-builder /out/owasp-ai-goat-policy-render-init /usr/local/libexec/owasp-ai-goat-policy-render-init
RUN test -f /usr/local/bin/node && test ! -L /usr/local/bin/node \
    && chown 0:0 /usr/bin/bwrap /usr/local/libexec/owasp-ai-goat-policy-render-supervisor /usr/local/libexec/owasp-ai-goat-policy-render-init \
    && chmod 0555 /usr/local/bin/node /usr/bin/bwrap /usr/local/libexec/owasp-ai-goat-policy-render-supervisor /usr/local/libexec/owasp-ai-goat-policy-render-init \
    && chmod -R a+rX /app/policy-render /server/services/secureshopPromptPolicyContract.js

ENV SECURESHOP_POLICY_RENDER_ENABLED=true \
    SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1
USER 10001:10001
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/node", "/app/policy-render/listener.js"]
