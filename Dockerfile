FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    binutils \
    libmagic1 \
    file && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN sed -i "s|'input_path': './test/example_inputs'|'input_path': '/example_inputs'|g" config/config.py && \
    sed -i "s|'output_path': './test/output'|'output_path': '/fuzzer_output'|g" config/config.py && \
    sed -i "s|'binary_path': './test/binaries'|'binary_path': '/binaries'|g" config/config.py

CMD ["python3", "main.py"]