FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10001 mcp && mkdir -p /app/data && chown -R mcp:mcp /app
USER mcp
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "deploy/xianyu_plus.py"]
CMD ["--stdio"]
