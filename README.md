# QSPHINCS

> ⚠️ **EXPERIMENTAL/POC STATUS**: This is a proof-of-concept implementation designed for research and educational purposes. Not recommended for production use without significant security review and hardening.

A comprehensive **proof-of-concept implementation** of a **three-layer hierarchical Certification Authority** using **SPHINCS+ post-quantum signatures** with **Gaussian Boson Sampling (GBS)** quantum hashing. This system demonstrates cryptographic agility, scalable certificate lifecycle management, and quantum-safe PKI architecture concepts.

![Python Version](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Status](https://img.shields.io/badge/Status-Experimental%2FPOC-orange.svg)
![Disclaimer](https://img.shields.io/badge/Disclaimer-Research%20Use%20Only-red.svg)

---

## ⚠️ IMPORTANT DISCLAIMER

**THIS IS A PROOF-OF-CONCEPT (POC) / EXPERIMENTAL IMPLEMENTATION**

### Critical Limitations:

🔴 **NOT SUITABLE FOR PRODUCTION** without significant additional work:
- ❌ No formal security audit or penetration testing
- ❌ Quantum hashing uses classical fallback (HMAC) - not true quantum computation
- ❌ SPHINCS+ integration is simplified, not hardware-optimized
- ❌ No persistent storage (data structures held in memory)
- ❌ No TLS/HTTPS security for communications
- ❌ Certificate revocation only in-memory (no CRL/OCSP)
- ❌ Token authentication is basic (no replay protection in deployment)
- ❌ Not battle-tested against real-world attacks
- ❌ No protection against side-channel attacks
- ❌ No hardware security module (HSM) support

### Experimental Features:

⚠️ **GBS Quantum Hashing**: Currently simulated via Strawberry Fields. Real quantum implementation requires actual quantum hardware (photonic processor).

⚠️ **Performance Metrics**: Benchmarks are for demonstration purposes and may not reflect production deployments.

⚠️ **Algorithm Selection**: SPHINCS+ variants are for research comparison, not production recommendation.

### Use Cases:

✅ **Suitable For:**
- Academic research and education
- Understanding post-quantum PKI architecture
- Proof-of-concept demonstrations
- Algorithm comparison and benchmarking
- Learning about certificate lifecycle management

❌ **NOT Suitable For:**
- Production PKI deployment
- Protecting sensitive data
- Real-world authentication systems
- Compliance with security standards (FIPS, etc.)

---

## 🌟 Overview

This project implements a **Post-Quantum Certification Authority** based on the academic paper *"$QSphincs$: A Quantum-Resistant Hash-Based Signature Scheme for Authentication in $QKD$ systems"*.

**Note**: This is a proof-of-concept implementation for research and educational purposes.

### Key Capabilities

✅ **Three-Layer Hierarchical PKI**
- Root CA → Intermediate CA (ICA) → End Entities
- Chain-of-trust validation
- Certificate lifecycle management

✅ **Post-Quantum Cryptography**
- SPHINCS+ digital signatures (NIST-standardized)
- Deterministic AES-based hash functions
- Quantum-safe key generation

✅ **Quantum Hashing**
- Gaussian Boson Sampling (GBS) integration
- Photonic computing for quantum-enhanced hashing
- Fallback to classical HMAC when quantum unavailable

✅ **Cryptographic Agility**
- Seamless algorithm switching
- Multiple SPHINCS+ variants (128f, 192f)
- Support for different security levels

✅ **Certificate Management**
- Automated issuance and revocation
- Token-based authentication (5-min validity)
- Certificate blacklisting (in-memory)
- Batch certificate generation

✅ **Research & Demonstration Features**
- Multiprocessing support for parallel execution demonstrations
- Comprehensive error handling (for proof-of-concept)
- Performance benchmarking (research metrics)
- Scalability testing demonstrations (5-1000+ clients)

---

## ✨ Features

### Core Capabilities

| Feature | Details |
|---------|---------|
| **Signature Algorithm** | SPHINCS+ (SPHINCS+-SHA2-128f-simple, SPHINCS+-SHA2-192f-simple) |
| **Hash Function** | AES-CTR tree-based hashing (deterministic, post-quantum secure) |
| **Quantum Integration** | Gaussian Boson Sampling (GBS) via Strawberry Fields |

### Advanced Features

- **Crypto-Agility Manager**: Switch algorithms at runtime (<1ms overhead)
- **Chain Validation**: Multi-level certificate chain verification
- **Performance Metrics**: Real-time throughput and latency measurement
- **Parallel Processing**: Multicore support for batch operations
- **Deterministic Behavior**: Same input always produces same signature
- **Error Recovery**: Graceful fallback mechanisms

---

## 🏗️ Architecture

### System Layers

```
┌─────────────────────────────────────────────────┐
│           End Entity Layer                       │
│  (Client Certificates, 5-min Token Validity)   │
└─────────────────┬───────────────────────────────┘
                  │ (Verified by)
                  ▼
┌─────────────────────────────────────────────────┐
│        Intermediate CA Layer (ICA)               │
│  (Certificate Issuance, Chain Building)         │
└─────────────────┬───────────────────────────────┘
                  │ (Verified by)
                  ▼
┌─────────────────────────────────────────────────┐
│            Root CA Layer                         │
│  (Trust Anchor, Root Certificate)               │
└─────────────────────────────────────────────────┘
```

### Component Architecture

```
┌──────────────────────────────────────────────────────────┐
│         Cryptographic Agility Manager                    │
│  (Algorithm Selection, Runtime Switching)               │
└──────┬──────────────────────────────────────────────┬────┘
       │                                              │
       ▼                                              ▼
┌──────────────────────┐                  ┌────────────────────┐
│  SPHINCS+ Provider   │                  │ GBS Hashing        │
│                      │                  │ Provider           │
│ - Key Generation     │                  │                    │
│ - Signing            │                  │ - Quantum Hash     │
│ - Verification       │                  │ - Classical        │
│ - Multi-variant      │                  │   Fallback         │
└──────┬──────────────┘                   └────────────────────┘
       │
       └──────────┬──────────────────┬──────────────────┐
                  │                  │                  │
                  ▼                  ▼                  ▼
           ┌────────────┐      ┌──────────┐      ┌──────────┐
           │ Root CA    │      │  ICA     │      │  End     │
           │            │      │          │      │ Entity   │
           │- Issues    │      │- Issues  │      │          │
           │  Root Cert │      │  EE Certs│      │- Token   │
           │            │      │          │      │- Auth    │
           └────────────┘      └──────────┘      └──────────┘
```

---

## 🛠️ Technology Stack

### Core Technologies

| Component | Technology | Version | Status |
|-----------|-----------|---------|--------|
| **Language** | Python | 3.10+ | ✅ Stable |
| **Quantum Framework** | Strawberry Fields | 0.23.0 | ⚠️ Simulation Only |
| **Cryptography** | PyCryptodome | 3.18.0+ | ✅ Stable |
| **Numerical** | NumPy, SciPy, SymPy | Latest | ✅ Stable |
| **Data Processing** | Pandas | 2.0.3+ | ✅ Stable |
| **Testing** | Pytest | 7.4.0+ | ✅ Stable |
| **Notebooks** | Jupyter | 1.0.0+ | ✅ Stable |

**⚠️ Important Note**: Strawberry Fields is used for quantum simulation only. Real quantum operations require photonic quantum hardware.

### Key Libraries

- **strawberryfields** (0.23.0): Photonic quantum computing (simulation)
- **thewalrus** (0.21.0): Hafnian computations for GBS
- **pycryptodome** (3.18.0): AES, HMAC, hashing
- **tensorflow** (2.15.0): ML optimization (GBS backend)
- **numpy/scipy**: Scientific computing

---

## 📦 Installation

> ⚠️ This is a proof-of-concept. Ensure you understand the limitations before using.

### Prerequisites

- Python 3.10 or higher
- pip or conda package manager
- 4GB RAM minimum (8GB recommended for full experiments)
- 2+ CPU cores (for parallel processing demonstrations)

### Step 1: Clone Repository

```bash
git clone https://github.com/tinkuaec319/QSPHINCS.git
cd QSPHINCS
```

### Step 2: Create Virtual Environment

```bash
# Using venv
python3.10 -m venv pqi_env
source pqi_env/bin/activate  # On Windows: pqi_env\Scripts\activate

# Or using conda
conda create -n pqi python=3.10
conda activate pqi
```

### Step 3: Install Dependencies

```bash
# Install all dependencies
pip install -r requirements.txt

# Or install SPHINCS package separately
pip install -r sphincs/requirements.txt
```

### Step 4: Verify Installation

```bash
python -c "import strawberryfields; import numpy; import pycryptodome; print('✓ All dependencies installed')"
```

**Note**: This verification only confirms dependencies are installed. It does not validate cryptographic security for production use.

---

## 🚀 Quick Start

> **POC/Demonstration Purpose**: These examples demonstrate the system architecture, not production-ready code.

### 1. Basic Demo (2-3 minutes)

```bash
# Run quick demonstration
python demo.py
```

Expected output:
```
================================================================================
           Quick Demonstration of Post-Quantum CA System           
================================================================================

--- 1. SPHINCS+ Provider Demo ---
  ✓ SPHINCS+ Provider initialized
  ✓ Keypair generated (pk: 32 bytes, sk: 64 bytes)
  ✓ Message signed and verified
  ...
```

**Note**: This demo uses simulated quantum hashing (Strawberry Fields). Real quantum operations require quantum hardware.

### 2. Full Implementation Notebook

```bash
# Launch Jupyter notebook
jupyter notebook CA_Implementation_And_Experiments.ipynb
```

This comprehensive notebook demonstrates:
- CA initialization and configuration
- Certificate generation and signing (POC only)
- Chain validation (simplified implementation)
- Token-based authentication (in-memory only)
- Performance metrics (for research comparison)

**Important**: Code in notebook is for educational purposes. Not suitable for production without significant hardening.

### 3. Run Experiments

```bash
python experiments_runner.py
```

This executes 5 research demonstration experiments:
1. **Single ICA Scaling** (5-500 clients) - POC scalability
2. **Two-ICA Load Distribution** (50-1000 clients) - Research comparison
3. **Certificate Verification** (50+ certificates) - Algorithm validation
4. **Algorithm Performance Comparison** - Benchmarking only
5. **Crypto-Agility Demonstration** - Architecture showcase

Results saved to CSV and JSON (for research analysis):
```
results/experiment_1_single_ica_scaling.csv
results/experiment_2_two_ica_distribution.csv
...
```

⚠️ **Performance Metrics**: These are POC benchmarks and do not reflect production-grade security implementations.

---

## 💡 Usage Examples

### Example 1: Initialize CA System

```python
from sphincs_ca_integration import (
    SPHINCSProvider,
    CertificateSigningAuthority
)

# Initialize SPHINCS+ provider
provider = SPHINCSProvider(variant="SPHINCS+-SHA2-128f-simple")
pk, sk = provider.generate_keypair()

# Initialize Root CA
root_ca = CertificateSigningAuthority(
    cn="Root-CA",
    public_key=pk,
    private_key=sk,
    ca_type="root"
)

# Issue certificate
cert = root_ca.issue_certificate(
    subject_cn="Intermediate-CA",
    subject_pk=intermediate_pk,
    validity_days=3650
)

print(f"✓ Certificate issued: {cert['serial_number']}")
```

### Example 2: Create and Verify Certificates

```python
# Create Intermediate CA
ica = CertificateSigningAuthority(
    cn="Intermediate-CA",
    public_key=intermediate_pk,
    private_key=intermediate_sk,
    ca_type="intermediate",
    issuer_cert=root_cert
)

# Issue end-entity certificate
ee_cert = ica.issue_certificate(
    subject_cn="user@example.com",
    subject_pk=user_pk,
    validity_days=365
)

# Verify certificate chain
is_valid = ica.validate_certificate_chain(
    certificate=ee_cert,
    chain=[root_cert, ica_cert],
    trusted_root_pk=root_pk
)

print(f"Certificate valid: {is_valid}")
```

### Example 3: Use Cryptographic Agility

```python
from sphincs_ca_integration import CryptoAgilityManager

# Create agility manager
agility = CryptoAgilityManager()

# Switch algorithms seamlessly
agility.select_algorithm("SPHINCS+-SHA2-192f-simple")
provider = agility.get_provider()

# Use new algorithm
pk, sk = provider.generate_keypair()
signature = provider.sign(message, sk)
is_valid = provider.verify(message, signature, pk)
```

### Example 4: Token-Based Authentication

```python
# Generate authentication token
token = ica.generate_authentication_token(
    client_id="client-123",
    validity_minutes=5
)

# Verify token
is_valid = ica.verify_authentication_token(token)
print(f"Token valid: {is_valid}")
```

---

## 📁 Project Structure

```
PQI_PKI_v2/
├── .gitignore                              # Git exclusions
├── .env.example                            # Environment configuration template
├── README.md                               # This file
├── requirements.txt                        # Python dependencies
│
├── CA_Implementation_And_Experiments.ipynb # Main implementation notebook
├── demo.py                                 # Quick demonstration script
├── demo_fast.py                            # Fast fallback demo (2-3 min)
├── experiments_runner.py                   # Comprehensive experiments
│
├── sphincs_ca_integration.py               # SPHINCS+ CA integration module
│                                           # (450+ LOC, core implementation)
│
├── sphincs/                                # SPHINCS+ package
│   ├── package/
│   │   ├── sphincs.py                     # SPHINCS+ implementation (with AES hash)
│   │   ├── gbs_hash.py                    # GBS hashing integration
│   │   ├── adrs.py                        # ADRS data structure
│   │   └── setup.py                       # Package setup
│   ├── src/
│   │   ├── sphincs.py                     # Core SPHINCS+ code
│   │   ├── wots.py                        # Winternitz one-time signatures
│   │   ├── xmss.py                        # eXtended Merkle Signature Scheme
│   │   ├── hypertree.py                   # Hypertree structure
│   │   ├── fors.py                        # Few-time OTS with Restart
│   │   ├── parameters.py                  # Parameter sets
│   │   └── ... (supporting modules)
│   ├── requirements.txt                   # SPHINCS package dependencies
│   └── SPHINCS_README.md                  # SPHINCS documentation
│
├── __pycache__/                            # Python bytecode (git ignored)
└── pki_gbs/                                # Virtual environment (git ignored)
```

### Key Files

| File | Lines | Purpose |
|------|-------|---------|
| `CA_Implementation_And_Experiments.ipynb` | 1,200+ | Main implementation with demonstrations |
| `sphincs_ca_integration.py` | 450+ | SPHINCS+ integration with crypto-agility |
| `experiments_runner.py` | 550+ | Comprehensive performance experiments |
| `demo.py` | 289 | Quick feature demonstrations |
| `sphincs/package/sphincs.py` | 1,200+ | Core SPHINCS+ with AES hash function |

---

## 📖 API Documentation

### SPHINCSProvider

```python
class SPHINCSProvider:
    """SPHINCS+ cryptographic provider"""
    
    def generate_keypair() -> Tuple[bytes, bytes]
        """Generate SPHINCS+ keypair (public_key, secret_key)"""
    
    def sign(message: bytes, secret_key: bytes) -> bytes
        """Sign message with secret key"""
    
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool
        """Verify signature"""
    
    def get_public_key(secret_key: bytes) -> bytes
        """Derive public key from secret key"""
```

### CertificateSigningAuthority

```python
class CertificateSigningAuthority:
    """CA operations for certificate lifecycle management"""
    
    def issue_certificate(subject_cn: str, subject_pk: bytes, 
                         validity_days: int) -> dict
        """Issue certificate to subject"""
    
    def revoke_certificate(serial_number: str) -> bool
        """Revoke certificate"""
    
    def verify_certificate(certificate: dict) -> bool
        """Verify single certificate"""
    
    def validate_certificate_chain(certificate: dict, chain: list,
                                  trusted_root_pk: bytes) -> bool
        """Validate full certificate chain"""
    
    def generate_authentication_token(client_id: str, 
                                     validity_minutes: int) -> dict
        """Generate time-limited authentication token"""
```

### CryptoAgilityManager

```python
class CryptoAgilityManager:
    """Seamless cryptographic algorithm switching"""
    
    def select_algorithm(algorithm_name: str) -> None
        """Switch to different algorithm"""
    
    def get_provider() -> Provider
        """Get current crypto provider"""
    
    def benchmark_algorithms() -> dict
        """Compare performance of all algorithms"""
```

---

## 🔐 Security Features

> ⚠️ **SECURITY NOTICE**: This is a POC implementation. It has NOT been audited and should NOT be used for production systems without significant hardening and professional security review.

### Cryptographic Security (POC Level)

- **Post-Quantum Foundation**: SPHINCS+ algorithm (NIST-standardized), simplified integration
- **Hash Implementation**: AES-based tree hashing (classical fallback, not true quantum)
- **Key Generation**: Demonstrates post-quantum key generation concepts
- **Signature Size**: ~7KB per signature (not optimized)

**Limitations**:
- ❌ No formal security proofs for this implementation
- ❌ Quantum hashing uses classical HMAC fallback
- ❌ Not constant-time implementations (vulnerable to timing attacks)
- ❌ No protection against side-channel attacks

### PKI Security (Demonstration Level)

- **Chain-of-Trust**: Multi-level verification (simplified)
- **Certificate Blacklisting**: In-memory only (no persistence)
- **Token Expiration**: Time-limited authentication (basic)
- **Operation Tracing**: Logging for demonstration

**Limitations**:
- ❌ No persistent revocation database
- ❌ No CRL/OCSP support
- ❌ Token storage is unencrypted
- ❌ No audit trail preservation

### Implementation Security (Research Grade)

- **No Hardcoded Secrets**: Configuration-based (still needs external key management)
- **Error Handling**: Graceful failure modes (information disclosure possible)
- **Input Validation**: Type and value checking (incomplete)
- **Lack of Security Hardening**: Not battle-tested against attacks

**Limitations**:
- ❌ No protection against injection attacks in all cases
- ❌ No rate limiting on operations
- ❌ No mutual authentication between components
- ❌ No secure communication channels

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install with dev dependencies
pip install -r requirements.txt pytest ipython jupyter

# Run tests
pytest tests/ -v

# Format code
black sphincs_ca_integration.py experiments_runner.py

# Check code quality
pylint sphincs_ca_integration.py
```

---

## 📚 Citation

If you use this implementation in your research, please cite:

```bibtex

@software{pqi_pki_2026,
  author = {PQI-PKI Development Team},
  title = {Post-Quantum Certification Authority System},
  url = {https://github.com/tinkuaec319/QSPHINCS.git},
  year = {2026}
}
```

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **SPHINCS+ Implementation**: Based on sphincs-python reference implementation
- **Strawberry Fields**: Xanadu's quantum computing framework
- **Academic Foundation**: QCNC 2025 paper by Tsili et al.

---

## 📞 Support

For issues, questions, or suggestions:

1. **GitHub Issues**: Report bugs and feature requests
2. **Discussions**: General questions and ideas
3. **Documentation**: See inline code comments and docstrings
4. **Jupyter Notebooks**: Run `CA_Implementation_And_Experiments.ipynb` for examples

---

## 🚀 Future Work

This POC demonstrates core concepts. Production implementation would require:

### Security Hardening Required
- [ ] Professional security audit and penetration testing
- [ ] Constant-time cryptographic implementations
- [ ] Side-channel attack protection
- [ ] Hardware security module (HSM) integration
- [ ] Secure key storage mechanisms
- [ ] Authenticated encryption for all communications

### Infrastructure & Deployment
- [ ] REST API server with TLS/HTTPS
- [ ] Database persistence (PostgreSQL, etc.)
- [ ] Key management system (KMS)
- [ ] Certificate revocation (CRL/OCSP)
- [ ] Audit logging and monitoring
- [ ] Docker containerization
- [ ] Kubernetes deployment templates

### Additional Cryptography
- [ ] Falcon-512/1024 signatures
- [ ] Dilithium variants
- [ ] Kyber/ML-KEM key encapsulation
- [ ] Real quantum hashing (requires quantum hardware)
- [ ] Hardware acceleration for SPHINCS+

### Operational Features
- [ ] Web UI dashboard for certificate management
- [ ] Multi-language client libraries
- [ ] ACME protocol support
- [ ] Enhanced monitoring and metrics
- [ ] Rate limiting and DDoS protection
- [ ] Load balancing for multiple CA instances

---

**Last Updated**: May 2026  
**Status**: Experimental/POC (Research Use Only)  
**Python Version**: 3.10+  
**Security Status**: NOT AUDITED - For Research Purposes Only
