FROM python:3.13-slim
RUN pip install --no-cache-dir django==5.1.4 gunicorn==23.0.0
WORKDIR /app
COPY app.py .
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "app:application"]
