FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1 AS seccomp-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*
COPY mcpSeccompFilter.c mcpSeccompProbe.c /build/
COPY owned-http/namespace-init.c owned-http/process-supervisor.c /build/
COPY policy-render/process-supervisor.c policy-render/policy-init.c /build/policy-render/
RUN mkdir -p /out \
    && gcc -O2 -Wall -Wextra -Werror /build/process-supervisor.c -o /out/dvaia-owned-http-supervisor \
    && gcc -O2 -Wall -Wextra -Werror /build/namespace-init.c -o /out/dvaia-owned-http-init \
    && gcc -O2 -Wall -Wextra -Werror /build/mcpSeccompFilter.c -lseccomp -o /tmp/mcp-seccomp-filter \
    && gcc -O2 -Wall -Wextra -Werror /build/mcpSeccompProbe.c -o /out/dvaia-mcp-seccomp-probe \
    && gcc -static -O2 -Wall -Wextra -Werror /build/policy-render/process-supervisor.c -o /out/dvaia-policy-render-supervisor \
    && gcc -static -O2 -Wall -Wextra -Werror /build/policy-render/policy-init.c -o /out/dvaia-policy-render-init \
    && /tmp/mcp-seccomp-filter /out/mcp-target.seccomp.bpf \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in arm64|amd64) ;; *) exit 65 ;; esac \
    && sha="$(sha256sum /out/mcp-target.seccomp.bpf | cut -d' ' -f1)" \
    && printf '{"arch":"%s","sha256":"%s","version":1}\n' "$arch" "$sha" > /out/mcp-target.seccomp.json \
    && chmod 0555 /out/dvaia-mcp-seccomp-probe /out/dvaia-policy-render-supervisor /out/dvaia-policy-render-init \
    && chmod 0444 /out/mcp-target.seccomp.bpf /out/mcp-target.seccomp.json

FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1

# Real coreutils the exploits exercise, bubblewrap for namespace isolation,
# gosu to drop privileges after seeding the lab filesystem as root.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash coreutils grep curl ca-certificates bubblewrap gosu procps tar util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
COPY index.js ./
COPY mcpTargets.js ./
COPY mcpProtectedState.js ./
COPY protected-operations ./protected-operations
COPY mcpPackageCatalog.js ./
COPY ownedTargetApi.js ./
COPY owned-http ./owned-http
COPY policy-render/executor.js policy-render/http-handler.js policy-render/worker.js ./policy-render/
COPY policy-render/assets ./policy-render/assets
# Generated packaging copy: tests require these bytes to equal the canonical
# server/services/secureshopPromptPolicyContract.js contract exactly.
COPY policy-render/secureshopPromptPolicyContract.js /server/services/secureshopPromptPolicyContract.js
COPY --from=seccomp-builder /out/dvaia-owned-http-supervisor /usr/local/libexec/dvaia-owned-http-supervisor
COPY --from=seccomp-builder /out/dvaia-owned-http-init /usr/local/libexec/dvaia-owned-http-init
COPY --from=seccomp-builder /out/dvaia-policy-render-supervisor /usr/local/libexec/dvaia-policy-render-supervisor
COPY --from=seccomp-builder /out/dvaia-policy-render-init /usr/local/libexec/dvaia-policy-render-init
COPY owned-http/worker.js /usr/local/libexec/dvaia-owned-http-worker.js
COPY owned-http/network-manifest.json /usr/local/libexec/dvaia-owned-http-manifest.json
COPY --from=seccomp-builder /out/dvaia-mcp-seccomp-probe /usr/local/libexec/dvaia-mcp-seccomp-probe
COPY --from=seccomp-builder /out/mcp-target.seccomp.bpf /usr/share/dvaia/mcp-target.seccomp.bpf
COPY --from=seccomp-builder /out/mcp-target.seccomp.json /usr/share/dvaia/mcp-target.seccomp.json
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY labfs /opt/lab-template
RUN test -f /usr/local/bin/node && test ! -L /usr/local/bin/node \
    && chown 0:0 /usr/bin/bwrap /usr/local/libexec/dvaia-policy-render-supervisor /usr/local/libexec/dvaia-policy-render-init \
    && chmod 0555 /usr/local/bin/node /usr/local/bin/entrypoint.sh /usr/bin/bwrap \
      /usr/local/libexec/dvaia-policy-render-supervisor /usr/local/libexec/dvaia-policy-render-init \
    && chmod -R a+rX /app/policy-render /server/services/secureshopPromptPolicyContract.js \
    && chmod -R a+rX /opt/lab-template

RUN node /app/owned-http/buildAssets.js

ENV SANDBOX_RUNNER_PORT=8090
EXPOSE 8090

# bubblewrap needs to configure namespaces at exec time; the container itself
# runs as root only long enough to seed files, then the runner drops to uid
# 10001 (see entrypoint). The legacy service can use non-root plain exec where
# user namespaces are unavailable, but that path is ungraded and cannot make
# the strict owner-scoped resource adapter ready. Fargate remains unqualified.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
