FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    RDRS_API_HOST=0.0.0.0 RDRS_API_PORT=8765
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Run as a non-root user; data/ and logs/ must be writable
RUN useradd --create-home rdrs && mkdir -p data/sandbox data/quarantine data/reports logs \
    && chown -R rdrs:rdrs /app
USER rdrs

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ['RDRS_API_PORT']+'/health')"

# Simulation mode stays ON (see config.yaml). Only the sandbox folder is watched.
CMD ["python", "-m", "app.main"]
