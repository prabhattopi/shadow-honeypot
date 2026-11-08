FROM python:3.12-slim

# Prevent Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY . .

# Expose SSH Deception Port (2222) and Web SOC Dashboard Port (8000)
EXPOSE 2222 8000

# Start script to run both SSH Daemon and Web Dashboard concurrently
CMD ["sh", "-c", "python daemon/ssh_server.py & python -m uvicorn dashboard.app:app --host 0.0.0.0 --port 8000"]