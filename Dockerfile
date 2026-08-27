FROM node:22.13-alpine@sha256:1322b1e3975e50d4841db1f23f536a8e72249e16a89e1dbbf16953afaa816d41 AS build
WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY tests ./tests
RUN npm run build && npm run compile

FROM node:22.13-alpine@sha256:1322b1e3975e50d4841db1f23f536a8e72249e16a89e1dbbf16953afaa816d41
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /workspace/dist ./dist
COPY migrations ./migrations
USER node
EXPOSE 8080
CMD ["node", "dist/main.js"]
