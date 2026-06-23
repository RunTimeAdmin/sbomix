FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:20-alpine
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY src/   ./src/
COPY bin/   ./bin/
COPY package.json ./
EXPOSE 3080
USER node
CMD ["node", "src/api/server.js"]
