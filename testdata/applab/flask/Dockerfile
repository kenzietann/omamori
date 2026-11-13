FROM python:3.13-slim
RUN pip install --no-cache-dir flask==3.1.0
WORKDIR /app
COPY app.py .
CMD ["python", "app.py"]
