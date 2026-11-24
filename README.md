# BuildQuorum

**BuildQuorum** is a deterministic software build attestation and supply-chain verification system. Independent validator nodes compile submitted source files deterministically, sign cryptographic attestations, reach quorum consensus, and record verified build hashes onto a tamper-evident blockchain ledger backed by Merkle proofs.

## Key Features

- **Deterministic Reproducible Builds:** Normalizes source files and compiles artifacts reproducibly so independent validators arrive at identical SHA-256 build hashes.
- **Multi-Validator Quorum Consensus:** Four independent validators (`V1`–`V4`) build, sign, and vote on each submission, requiring a 3-of-4 quorum to finalize a block.
- **Compromised Publisher & Fault Detection:**
  - Flags packages when a publisher's artifact hash diverges from the validator quorum's consensus build hash (`FLAGGED` vs. `OK`).
  - Supports injecting dishonest ("lying") validator behavior to demonstrate quorum resilience and fault tracking.
- **Tamper-Evident Ledger & Merkle Proofs:**
  - Chained blocks with cryptographic proposer and validator signatures, Merkle roots, and per-validator Merkle inclusion proofs.
  - Built-in chain validation, block tamper simulation, and snapshot recovery.
- **Independent Artifact Verification:** Upload any artifact to verify its SHA-256 hash against the immutable consensus record (`VERIFIED`, `TAMPERED`, or `NOT RECOGNIZED`).

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn, Pydantic
- **Cryptography & Ledger:** SHA-256 Merkle trees, asymmetric validator/proposer signatures, JSON-backed chain & snapshot persistence
- **Testing:** `pytest`

## Getting Started

### 1. Set Up the Backend
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install fastapi uvicorn pydantic cryptography pytest python-multipart