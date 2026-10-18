FROM docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1
WORKDIR /app
COPY index.js ./
ENV ROGUE_MCP_PORT=8091
EXPOSE 8091
USER node
CMD ["node", "index.js"]
