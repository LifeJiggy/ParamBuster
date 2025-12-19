# ParamBuster Dockerfile
# Build with: docker build -t parambuster .
# Run with: docker run -it parambuster -u https://example.com

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV CHROME_BIN=/usr/bin/chromium-browser
ENV CHROMEDRIVER_PATH=/usr/lib/bin/chromedriver

# Install system dependencies
RUN apt-get update && apt-get install -y \
    chromium-browser \
    chromium-chromedriver \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libxss1 \
    libxtst6 \
    xdg-utils \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ParamBuster.py .
COPY lists/ ./lists/
COPY strong_wordlist/ ./strong_wordlist/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash parambuster
RUN chown -R parambuster:parambuster /app
USER parambuster

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import ParamBuster; print('ParamBuster is healthy')" || exit 1

# Set entrypoint
ENTRYPOINT ["python", "ParamBuster.py"]

# Default command
CMD ["--help"]