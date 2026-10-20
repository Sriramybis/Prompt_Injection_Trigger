FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server/ server/
ENV PORT=8080
CMD ["sh", "-c", "uvicorn server.pi_guard_server:app --host 0.0.0.0 --port ${PORT}"]
