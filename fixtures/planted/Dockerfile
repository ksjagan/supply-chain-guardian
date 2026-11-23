# Planted Dockerfile fixture for testing supply chain checks
FROM node:latest

WORKDIR /app
COPY . .

# Unsafe piped shell execution & runs as root (no USER)
RUN curl -sSL https://install.example.com/setup.sh | sh

CMD ["node", "index.js"]
