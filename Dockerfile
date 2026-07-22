FROM python:3.11-slim

# Create non-root user 65532:65532
RUN groupadd -g 65532 verifier && useradd -u 65532 -g verifier -m verifier

WORKDIR /verifier
COPY verifier_run_p90_08b.py /verifier/verifier_run_p90_08b.py
RUN chmod 755 /verifier/verifier_run_p90_08b.py

USER 65532:65532

ENTRYPOINT ["python3", "/verifier/verifier_run_p90_08b.py"]
