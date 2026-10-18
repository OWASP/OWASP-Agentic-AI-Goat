FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1 AS template-helper-builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY policy-render/process-supervisor.c listing-template/template-init.c /build/
RUN mkdir -p /out \
    && gcc -static -O2 -Wall -Wextra -Werror /build/process-supervisor.c -o /out/dvaia-listing-template-supervisor \
    && gcc -static -O2 -Wall -Wextra -Werror /build/template-init.c -o /out/dvaia-listing-template-init \
    && chmod 0555 /out/dvaia-listing-template-supervisor /out/dvaia-listing-template-init

FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY listing-template/listener.js listing-template/executor.js listing-template/http-handler.js \
    listing-template/worker.js listing-template/strict-helpers.js \
    listing-template/secureshopListingTemplateExecutorContract.js ./listing-template/
COPY policy-render/assets ./policy-render/assets
COPY listing-template/secureshopListingTemplateExecutorContract.js /server/services/secureshopListingTemplateExecutorContract.js
COPY --from=template-helper-builder /out/dvaia-listing-template-supervisor /usr/local/libexec/dvaia-listing-template-supervisor
COPY --from=template-helper-builder /out/dvaia-listing-template-init /usr/local/libexec/dvaia-listing-template-init
RUN test -f /usr/local/bin/node && test ! -L /usr/local/bin/node \
    && chown 0:0 /usr/bin/bwrap /usr/local/libexec/dvaia-listing-template-supervisor /usr/local/libexec/dvaia-listing-template-init \
    && chmod 0555 /usr/local/bin/node /usr/bin/bwrap /usr/local/libexec/dvaia-listing-template-supervisor /usr/local/libexec/dvaia-listing-template-init \
    && chmod -R a+rX /app/listing-template /server/services/secureshopListingTemplateExecutorContract.js
ENV SECURESHOP_LISTING_TEMPLATE_ENABLED=true \
    SECURESHOP_LISTING_TEMPLATE_MAX_CONCURRENT=1
USER 10001:10001
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/node", "/app/listing-template/listener.js"]
