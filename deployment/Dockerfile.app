FROM node:26.10.0-bookworm-slim AS build
ENV PUPPETEER_SKIP_DOWNLOAD=true

RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY client/package.json client/package-lock.json ./client/
RUN npm --prefix client ci
COPY . .
RUN npm run build
# client/node_modules is build-only: the server serves client/build. Dropping it
# keeps ~333MB of build tooling out of the runtime image and its push.
RUN rm -rf client/node_modules

# Pre-bake the RAG embedding model (Xenova/all-MiniLM-L6-v2, q8) into the image
# so the runtime boots fully offline (HF_HUB_OFFLINE=1) with no download. The
# runtime loader (ragVectorStore.js) resolves <cacheDir>/Xenova/all-MiniLM-L6-v2
# with local_files_only, so the baked files must land at that exact relative path.
ENV TRANSFORMERS_CACHE=/opt/hf-cache HF_HOME=/opt/hf-cache
RUN node -e "const{pipeline,env}=require('@huggingface/transformers');env.cacheDir='/opt/hf-cache';pipeline('feature-extraction','Xenova/all-MiniLM-L6-v2',{dtype:'q8',device:'cpu'}).then(async p=>{const o=await p('hello',{pooling:'mean',normalize:true});const dim=o.dims?o.dims[o.dims.length-1]:o.data.length;if(dim!==384)throw new Error('bad embedding dim '+dim);console.log('model baked ok dim',dim);}).catch(e=>{console.error('BAKE FAILED',e.message);process.exit(1)})"
# Fail the build if the baked cache cannot load fully offline — catches a broken
# bake here, at build time, instead of at the conference.
RUN HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 node -e "const{pipeline,env}=require('@huggingface/transformers');env.allowRemoteModels=false;env.cacheDir='/opt/hf-cache';pipeline('feature-extraction',require('path').resolve('/opt/hf-cache','Xenova/all-MiniLM-L6-v2'),{dtype:'q8',device:'cpu'}).then(async p=>{const o=await p('hi',{pooling:'mean',normalize:true});console.log('OFFLINE RAG OK',(o.dims||[o.data.length]).join('x'));}).catch(e=>{console.error('OFFLINE RAG FAILED',e.message);process.exit(1)})"

FROM node:26.10.0-bookworm-slim AS runtime
# chromium-sandbox provides the SUID helper Chromium needs to keep its sandbox
# locally. On Fargate the SYS_ADMIN capability is not available, so the app
# launches Chromium with --no-sandbox when BROWSER_NO_SANDBOX=1 (set only in the
# AWS task); the container is the isolation boundary there. Locally the env var
# is unset and the real sandbox is used. See docs/environment-qualification.md.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates chromium chromium-sandbox tini \
    && rm -rf /var/lib/apt/lists/*
# Amazon RDS presents a certificate chained to the Amazon RDS CA, which is not
# in Node's default trust store. Trusting this bundle keeps full certificate
# verification ON (rejectUnauthorized stays true) instead of disabling TLS
# validation to reach the database.
ENV NODE_ENV=production PORT=8081 PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    NODE_EXTRA_CA_CERTS=/etc/ssl/rds/rds-ca.pem \
    TRANSFORMERS_CACHE=/home/node/.cache/huggingface \
    HF_HOME=/home/node/.cache/huggingface
WORKDIR /app
# Separate COPY layers keep any single blob well under the size that makes a
# registry push fragile, and let unchanged dependencies stay cached.
COPY --from=build /app/node_modules /app/node_modules
COPY --from=build /app/client /app/client
COPY --from=build /app/server /app/server
COPY --from=build /app/db /app/db
COPY --from=build /app/scripts /app/scripts
COPY --from=build /app/agent-host /app/agent-host
COPY --from=build /app/sidecars /app/sidecars
COPY --from=build /app/deployment /app/deployment
COPY --from=build /app/package.json /app/package-lock.json /app/
COPY --from=build /app/deployment/rds-ca-us-west-2.pem /etc/ssl/rds/rds-ca.pem
# Pre-baked RAG embedding model cache (built in the build stage). Lands where the
# runtime TRANSFORMERS_CACHE/HF_HOME point, so the model loads offline at boot.
COPY --from=build /opt/hf-cache /home/node/.cache/huggingface
# The application refuses to start unless its data root is exactly mode 0700
# and owned by the running user (scripts/application-data-root.js).
# The RAG embedding model (Xenova/all-MiniLM-L6-v2) is PRE-BAKED into the image
# at build time and copied to this cache (above), so the runtime loads it fully
# offline (HF_HUB_OFFLINE=1) with no download. The app runs as "node", so the
# cache directory must be owned by it, otherwise loading fails with EACCES and
# every RAG endpoint returns 503.
RUN mkdir -p /app/server/logs /app/server/uploads /home/node/.owasp-ai-goat \
      /home/node/.cache/huggingface \
    && chown -R node:node /app/server/logs /app/server/uploads \
      /home/node/.owasp-ai-goat /home/node/.cache \
    && chmod 700 /home/node/.owasp-ai-goat
USER node
EXPOSE 8081
# Provisioning/migrations are a separate single-owner deployment operation.
ENTRYPOINT ["/usr/bin/tini", "--"]
# The entrypoint materialises SecureShop's private reset key file from its
# injected secret before starting the application. It is a no-op when that
# secret is absent.
CMD ["node", "deployment/entrypoint.js"]
