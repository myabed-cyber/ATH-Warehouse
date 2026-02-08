# syntax=docker/dockerfile:1
FROM node:20-slim

# Install CA certificates for outbound TLS (Supabase/HTTP APIs)
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

# Bundle app source
COPY . .

# Run as non-root (node user exists in the base image)
RUN chown -R node:node /app
USER node

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

CMD ["node", "server.js"]
