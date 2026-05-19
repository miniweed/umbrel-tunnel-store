FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js ./
COPY api-spec ./api-spec
COPY lib ./lib
COPY public ./public
COPY docker-entrypoint.sh ./

RUN mkdir -p /data \
  && chown -R node:node /app /data \
  && chmod 755 /app/docker-entrypoint.sh

USER node

EXPOSE 3000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
