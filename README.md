# SICA External Independent Verifier & Trust Root

This repository (`WSRodrig/sica-external-verifier`) serves as the **Independent External Trust Domain and Verification Authority** for the SICA/autocycle self-improvement architecture.

## Architecture
- **Isolated Execution:** Executes `p90_08b_handoff.tar.gz` bundles in isolated Docker containers with `--read-only` root mounts, `--network none`, and unprivileged non-root user `65532:65532`.
- **Cryptographic Attestations:** Issues GitHub OIDC artifact attestations (`actions/attest`) over evidence certificates and ledger checkpoint receipts.
- **Administrative Independence:** Operates under strict environment protection policies (`p90-08b-production`) and branch protection rules.
