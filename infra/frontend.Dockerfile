FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN corepack pnpm install --frozen-lockfile
COPY . .
ENV THREATLENS_LOCAL=1
ENV NEXT_TELEMETRY_DISABLED=1
RUN corepack pnpm exec next build
FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
USER 10001:10001
EXPOSE 3000
CMD ["node", "server.js"]
