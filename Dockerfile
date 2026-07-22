FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

# Create non-root user 65532:65532
RUN groupadd -g 65532 verifier && useradd -u 65532 -g verifier -m verifier

WORKDIR /verifier
COPY verifier_run_p90_08b.py /verifier/verifier_run_p90_08b.py
RUN chmod 755 /verifier/verifier_run_p90_08b.py

USER 65532:65532

ENTRYPOINT ["python3", "/verifier/verifier_run_p90_08b.py"]
