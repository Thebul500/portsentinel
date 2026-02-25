# Build stage — compile native dependencies
FROM node:20-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Production stage
FROM node:20-alpine

RUN apk add --no-cache libstdc++

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
COPY src/ ./src/
COPY bin/ ./bin/

RUN mkdir -p /data

ENV NODE_ENV=production

ENTRYPOINT ["node", "bin/portsentinel.js"]
