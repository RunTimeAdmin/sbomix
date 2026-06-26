FROM node:20-alpine AS deps
WORKDIR /app
# CLI deps (published to npm)
COPY package*.json ./
RUN npm ci --omit=dev
# Server-only deps (never published to npm)
COPY src/api/package*.json ./src/api/
RUN npm ci --omit=dev --prefix ./src/api

FROM node:20-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY --from=deps /app/node_modules        ./node_modules
COPY --from=deps /app/src/api/node_modules ./src/api/node_modules
COPY src/   ./src/
COPY bin/   ./bin/
COPY package.json ./
EXPOSE 3080
USER node
CMD ["node", "src/api/server.js"]
