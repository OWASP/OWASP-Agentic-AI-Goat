FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1
WORKDIR /app
COPY index.js ./
ENV SSRF_TARGET_PORT=9099
EXPOSE 9099
USER node
CMD ["node", "index.js"]
