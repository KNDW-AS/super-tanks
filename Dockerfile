FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev curl && \
    rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Create data directories
RUN mkdir -p data memory/hierarchical config

# Default port
EXPOSE 8765

# NOTE: the agent main loop (main_loop.py) and the dashboard API are not part of
# the open-source edition. This image therefore runs the environment check and
# the test suite; a private deployment overrides CMD with its own entry point.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -m supertanks doctor || exit 1

CMD ["python", "-m", "supertanks", "doctor"]
