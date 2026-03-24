FROM python:3.13-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Copy and install
COPY setup.py .
COPY cloudpilot/ cloudpilot/
RUN pip install --no-cache-dir -e .

# Expose dashboard port
EXPOSE 8080

# Default: start dashboard on all interfaces
ENV CLOUDPILOT_CORS_ORIGINS="*"
CMD ["cloudpilot", "dashboard", "--host", "0.0.0.0", "--port", "8080"]
