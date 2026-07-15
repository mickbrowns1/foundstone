FROM python:3.12-slim

WORKDIR /app

COPY *.py .

# No third-party deps — stdlib only
CMD ["python", "-u", "generate_logs.py"]
