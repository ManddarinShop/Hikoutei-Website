# Hikoutei QA harness — local-only scenario fuzzing skeleton.
FROM node:22.13-alpine

WORKDIR /app

# Production deps only (runtime uses node's built-in type stripping).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src

ENV NODE_ENV=production
# Ephemeral database by design: every (re)start is a clean slate, so a
# recorded seed always replays the identical run.
ENV QA_DB_PATH=/tmp/qa.sqlite

EXPOSE 3201
CMD ["node", "--experimental-strip-types", "src/server.ts"]
