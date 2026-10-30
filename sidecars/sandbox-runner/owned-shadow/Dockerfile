# Local owned shadow service only. Frozen AWS/full-app deployment assets are untouched.
FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libseccomp-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY owned-shadow/package.json owned-shadow/package-lock.json ./
RUN --mount=type=secret,id=npm_ca if [ -f /run/secrets/npm_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/npm_ca; fi; npm ci --ignore-scripts --no-audit --no-fund
COPY owned-shadow ./owned-shadow
COPY owned-http ./owned-http
COPY mcpSeccompFilter.c mcpSeccompProbe.c ./
RUN mkdir -p /out \
 && node -e "const f=require('node:fs');f.writeFileSync('/build/shadow-init.c',f.readFileSync('/build/owned-http/namespace-init.c','utf8').replaceAll('owasp-ai-goat-owned-http','owasp-ai-goat-owned-shadow'))" \
 && gcc -O2 -Wall -Wextra -Werror shadow-init.c -o /out/owasp-ai-goat-owned-shadow-init \
 && gcc -O2 -Wall -Wextra -Werror owned-http/process-supervisor.c -o /out/owasp-ai-goat-owned-shadow-supervisor \
 && gcc -O2 -Wall -Wextra -Werror mcpSeccompFilter.c -lseccomp -o /tmp/filter \
 && gcc -O2 -Wall -Wextra -Werror mcpSeccompProbe.c -o /out/owasp-ai-goat-mcp-seccomp-probe \
 && /tmp/filter /out/mcp-target.seccomp.bpf \
 && node_modules/.bin/esbuild owned-shadow/worker.js --bundle --platform=node --format=cjs --outfile=/out/owasp-ai-goat-owned-shadow-worker.js \
 && arch="$(dpkg --print-architecture)" \
 && sha="$(sha256sum /out/mcp-target.seccomp.bpf | cut -d' ' -f1)" \
 && printf '{"arch":"%s","sha256":"%s","version":1}\n' "$arch" "$sha" > /out/mcp-target.seccomp.json

FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1
RUN apt-get update && apt-get install -y --no-install-recommends bash coreutils grep curl ca-certificates bubblewrap gosu procps tar util-linux && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY mcpTargets.js mcpProtectedState.js mcpPackageCatalog.js ./
COPY protected-operations/operationStore.js ./protected-operations/operationStore.js
COPY owned-http/canonical.js ./owned-http/canonical.js
COPY owned-shadow ./owned-shadow
COPY labfs /opt/lab-template
COPY --from=build /out/owasp-ai-goat-owned-shadow-init /out/owasp-ai-goat-owned-shadow-supervisor /out/owasp-ai-goat-owned-shadow-worker.js /out/owasp-ai-goat-mcp-seccomp-probe /usr/local/libexec/
COPY --from=build /out/mcp-target.seccomp.bpf /out/mcp-target.seccomp.json /usr/share/owasp-ai-goat/
COPY owned-http/network-manifest.json /usr/local/libexec/owasp-ai-goat-owned-shadow-manifest.json
RUN chmod 0555 /usr/local/bin/node /usr/local/libexec/owasp-ai-goat-mcp-seccomp-probe \
 && chmod 0444 /usr/share/owasp-ai-goat/mcp-target.seccomp.bpf /usr/share/owasp-ai-goat/mcp-target.seccomp.json \
 && chmod -R a+rX /opt/lab-template \
 && node /app/owned-shadow/buildAssets.js \
 && node -e "require('./owned-shadow/service')"
USER 10001:10001
EXPOSE 8092
CMD ["node", "/app/owned-shadow/service.js"]
