FROM node:18-alpine

WORKDIR /app/backend

COPY backend/package*.json ./
RUN npm install

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

EXPOSE 3000

CMD ["node", "server.js"]