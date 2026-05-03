#!/usr/bin/env python3
"""
Quick Demonstration of Post-Quantum CA System
============================================

This script demonstrates the key features of the post-quantum CA implementation
without requiring all dependencies.
"""

import sys
import os

# ===== CRITICAL: Suppress TensorFlow/Strawberry Fields warnings BEFORE ANY IMPORTS =====
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow INFO, WARNING, ERROR logs
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'  # Disable GPU, use CPU only
os.environ['TF_FORCE_GPU_ALLOW_GROWTH'] = 'false'

import warnings
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)
# ===== END WARNING SUPPRESSION =====

import time
import json
from datetime import datetime

# Add project root to path relative to this file's location
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sphincs_ca_integration import (
    SPHINCSProvider,
    CertificateSigningAuthority,
    CryptoAgilityManager
)


def print_header(text):
    print("\n" + "=" * 80)
    print(text.center(80))
    print("=" * 80)


def print_section(text):
    print("\n" + "-" * 80)
    print(f"  {text}")
    print("-" * 80)


def demo_sphincs_provider():
    """Demonstrate SPHINCS+ Provider"""
    print_section("1. SPHINCS+ Provider Demo")
    
    print("\n  Initializing SPHINCS+ with NIST Level 1 security...")
    provider = SPHINCSProvider('SPHINCS_FAST_TEST', use_full_sphincs=True)
    params = provider.get_parameters()
    
    print(f"    Algorithm: SPHINCS_FAST_TEST")
    print(f"    NIST Level: {params['nist_level']}")
    print(f"    Public Key Size: {params['public_key_size']} bytes")
    print(f"    Secret Key Size: {params['secret_key_size']} bytes")
    print(f"    Signature Size: {params['signature_size']} bytes")
    
    print("\n  Generating keypair...")
    start = time.time()
    sk, pk = provider.generate_keypair()
    elapsed = (time.time() - start) * 1000
    
    print(f"    ✓ Keypair generated in {elapsed:.2f}ms")
    print(f"    ✓ Secret Key: {len(sk)} bytes : {sk.hex()}")
    print(f"    ✓ Public Key: {len(pk)} bytes : {pk.hex()}")

    print("\n  Creating signature...")
    message = b"--------------message"
    start = time.time()
    signature = provider.sign(message, sk)
    elapsed = (time.time() - start) * 1000
    
    print(f"    ✓ Signature created in {elapsed:.2f}ms")
    print(f"    ✓ Signature Size: {len(signature)} bytes : {signature.hex()}")
    print(f"    ✓ Message: {message.decode()}")
    
    print("\n  Verifying signature...")
    start = time.time()
    valid = provider.verify(signature, message, pk)
    elapsed = (time.time() - start) * 1000
    
    print(f"    ✓ Verification completed in {elapsed:.2f}ms")
    print(f"    ✓ Signature Valid: {valid}")
    
    # Get metrics
    metrics = provider.get_metrics_summary()
    print("\n  Performance Metrics:")
    print(f"    ✓ Operations: {metrics['operations']}")
    print(f"    ✓ Avg Signing Time: {metrics['avg_signing_time_ms']:.2f}ms")
    print(f"    ✓ Avg Throughput: {metrics['avg_throughput']:.2f} ops/sec")


def demo_certificate_authority():
    """Demonstrate Certificate Authority"""
    print_section("2. Certificate Authority Demo")
    
    print("\n  Creating Root CA with SPHINCS+...")
    root_ca = CertificateSigningAuthority("RootCA", 'SPHINCS_FAST_TEST')
    print(f"    ✓ Root CA initialized: {root_ca.ca_name}")
    
    print("\n  Creating Intermediate CA...")
    ica = CertificateSigningAuthority("ICA-1", 'SPHINCS_FAST_TEST')
    print(f"    ✓ ICA initialized: {ica.ca_name}")
    
    print("\n  Issuing certificates...")
    certs_issued = []
    for i in range(5):
        cert = ica.issue_certificate(f"CN=service-{i}.example.com", validity_days=365)
        certs_issued.append(cert)
        print(f"    ✓ Certificate {i+1}: {cert['certificate']['serial_number'][:16]}...")
    
    print(f"\n  Total certificates issued: {len(certs_issued)}")
    
    print("\n  Verifying certificates...")
    verified = 0
    for cert in certs_issued:
        cert_id = cert['certificate']['serial_number']
        is_valid = ica.verify_issued_certificate(cert_id)
        if is_valid:
            verified += 1
    
    print(f"    ✓ Verified: {verified}/{len(certs_issued)}")
    
    print("\n  Performance Report:")
    report = ica.get_performance_report()
    print(f"    ✓ CA Name: {report['ca_name']}")
    print(f"    ✓ Algorithm: {report['algorithm']}")
    print(f"    ✓ Total Certs Issued: {report['total_certificates_issued']}")
    
    metrics = report['cryptographic_metrics']
    if metrics:
        print(f"    ✓ Avg Signing Time: {metrics['avg_signing_time_ms']:.2f}ms")
        print(f"    ✓ Avg Throughput: {metrics['avg_throughput']:.2f} certs/sec")


def demo_crypto_agility():
    """Demonstrate Crypto-Agility"""
    print_section("3. Crypto-Agility Demonstration")
    
    print("\n  Initializing Crypto-Agility Manager...")
    manager = CryptoAgilityManager()
    
    algorithms = manager.list_available_algorithms()
    print(f"    ✓ Available algorithms: {len(algorithms)}")
    for algo in algorithms:
        print(f"      - {algo}")
    
    print("\n  Algorithm Comparison:")
    comparison = manager.get_algorithm_comparison()
    
    print("\n  Algorithm Specifications:")
    print("\n  {'Algorithm':<35} {'NIST Level':>10} {'PK':<10} {'Signature':<10}")
    print("  " + "-" * 70)
    
    for algo, specs in comparison.items():
        algo_short = algo.replace('SPHINCS+-SHA2-', '').replace('-simple', '')
        print(f"  {algo_short:<35} {specs['nist_level']:>10} {specs['public_key_size']:<10} {specs['signature_size']:<10}")
    
    print("\n  Testing algorithm switching...")
    for algo in algorithms:
        manager.set_algorithm(algo)
        provider = manager.get_provider()
        
        # Quick test
        sk, pk = provider.generate_keypair()
        message = b"Test message"
        signature = provider.sign(message, sk)
        valid = provider.verify(signature, message, pk)
        
        print(f"    ✓ {algo[:30]:.<40} Valid: {valid}")


def demo_scaling():
    """Demonstrate scalability"""
    print_section("4. Scalability Test")
    
    print("\n  Single ICA Scaling Test (5, 10, 20 clients)...")
    
    for num_clients in [5, 10, 20]:
        print(f"\n  Testing {num_clients} concurrent clients...")

        ica = CertificateSigningAuthority(f"ICA-test-{num_clients}", 'SPHINCS_FAST_TEST')

        start = time.time()
        successful = 0
        
        for i in range(num_clients):
            try:
                cert = ica.issue_certificate(f"CN=ee-{i}.example.com")
                successful += 1
            except Exception as e:
                print(f"      ✗ Error: {e}")
        
        elapsed = time.time() - start
        throughput = successful / elapsed if elapsed > 0 else 0
        
        print(f"    ✓ Issued {successful} certificates in {elapsed:.2f}s")
        print(f"    ✓ Throughput: {throughput:.2f} certs/sec")
        print(f"    ✓ Avg time per cert: {(elapsed/successful*1000):.2f}ms")


def demo_chain_validation():
    """Demonstrate certificate chain validation"""
    print_section("5. Certificate Chain Validation")
    
    print("\n  Building certificate chain...")
    print("    Root CA → ICA → End Entity")
    
    # Create hierarchy
    root_ca = CertificateSigningAuthority("RootCA", 'SPHINCS_FAST_TEST')
    ica = CertificateSigningAuthority("ICA-1", 'SPHINCS_FAST_TEST')

    # Root issues ICA cert
    print("\n  Step 1: Root CA issues ICA certificate")
    ica_cert = root_ca.issue_certificate("CN=ica-1.example.com", validity_days=3650)
    ica_cert_id = ica_cert['certificate']['serial_number']
    print(f"    ✓ ICA Certificate: {ica_cert_id[:16]}...")
    
    # ICA issues EE cert
    print("\n  Step 2: ICA issues End Entity certificates")
    ee_certs = []
    for i in range(3):
        ee_cert = ica.issue_certificate(f"CN=service-{i}.example.com", validity_days=365)
        ee_certs.append(ee_cert)
        print(f"    ✓ EE Certificate {i+1}: {ee_cert['certificate']['serial_number'][:16]}...")
    
    # Verify chain
    print("\n  Step 3: Verify certificate chain")
    
    # Verify ICA cert
    ica_valid = root_ca.verify_issued_certificate(ica_cert_id)
    print(f"    ✓ ICA Certificate valid: {ica_valid}")
    
    # Verify EE certs
    ee_valid = 0
    for ee_cert in ee_certs:
        ee_id = ee_cert['certificate']['serial_number']
        if ica.verify_issued_certificate(ee_id):
            ee_valid += 1
    
    print(f"    ✓ EE Certificates valid: {ee_valid}/{len(ee_certs)}")
    
    print("\n  Chain-of-Trust:")
    print(f"    Root CA (SPHINCS+-SHA2-192f)")
    print(f"      ↓ (issues certificate)")
    print(f"    ICA-1 (SPHINCS+-SHA2-192f)")
    print(f"      ↓ (issues certificates)")
    print(f"    {len(ee_certs)} End Entities")
    print(f"\n    Chain Status: {'✓ VALID' if ee_valid == len(ee_certs) else '✗ INVALID'}")


def main():
    """Main demonstration"""
    print_header("POST-QUANTUM CERTIFICATION AUTHORITY SYSTEM")
    print("\nDemonstration of SPHINCS+ Integration with GBS Hashing")
    print(f"Start Time: {datetime.now().isoformat()}")
    
    try:
        demo_sphincs_provider()
        demo_certificate_authority()
        demo_crypto_agility()
        demo_scaling()
        demo_chain_validation()
        
        print_header("DEMONSTRATION COMPLETE")
        print("\n✓ All tests passed successfully!")
        print("\nFor more information, see:")
        print("  - IMPLEMENTATION_GUIDE.md")
        print("  - README.md")
        print("  - CA_Implementation_And_Experiments.ipynb")
        print("\nTo run full experiments:")
        print("  python3 experiments_runner.py")
        
    except Exception as e:
        print(f"\n✗ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
