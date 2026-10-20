FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinel/ sentinel/
COPY leash/ leash/
COPY demo/ demo/
COPY pytest.ini .
CMD ["python", "-m", "sentinel.trap", "watch", "--loop"]
