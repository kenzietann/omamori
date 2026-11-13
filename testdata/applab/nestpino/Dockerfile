FROM node:22-slim
WORKDIR /app
COPY package.json tsconfig.json ./
RUN npm install --no-audit --no-fund
COPY src src
RUN npx tsc -p . && npm prune --omit=dev
CMD ["node", "dist/main.js"]
