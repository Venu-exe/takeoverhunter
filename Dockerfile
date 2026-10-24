FROM python:3.11-slim
WORKDIR /app
COPY . /app
EXPOSE 8765
CMD ["python", "takeoverhunter.py", "--serve", "--port", "8765", "--db", "/data/takeoverhunter.db"]
VOLUME ["/data"]
