# Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY Login.proto .
COPY Login_pb2.py .
COPY proto_pure.py .
COPY config.py .
COPY decrypt_pure.py .
COPY bypass_pure_python.py .
COPY uid_generator_pb2.py .

# Generate protobuf classes (if needed)
RUN python -c "import Login_pb2; print('Protobuf modules loaded successfully')"

# Create a simple web interface wrapper
COPY app.py .

# Expose ports
EXPOSE 20010 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start the application
CMD ["python", "app.py"]