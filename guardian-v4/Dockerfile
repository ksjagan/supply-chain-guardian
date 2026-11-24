FROM python:3.11-slim

# Create non-root user
RUN groupadd -r guardian && useradd -r -g guardian -m -d /home/guardian guardian

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    nodejs \
    npm \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R guardian:guardian /app
USER guardian

EXPOSE 8501

ENTRYPOINT ["streamlit", "run", "guardian/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
