FROM node:latest

ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

WORKDIR /app

RUN curl -sSL https://install.example.com/setup.sh | sh

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000
CMD ["node", "src/index.js"]
