FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY src ./src

RUN mkdir -p /var/log/custom-waf

ENV LISTEN_PORT=8082
ENV UPSTREAM_URL=http://dvwa:80
ENV LOG_FILE=/var/log/custom-waf/waf.log

EXPOSE 8082

CMD ["npm", "start"]
