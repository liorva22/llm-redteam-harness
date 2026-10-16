FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY redteam ./redteam
RUN pip install --no-cache-dir .
COPY suites ./suites
EXPOSE 8000
CMD ["uvicorn", "redteam.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
