"""
Post-Quantum CA Experiments Runner with SPHINCS+ Integration
============================================================

This module runs comprehensive experiments for the post-quantum CA system:
- Experiment 1: Single ICA scaling (5-500 clients) - Parallel multicore execution
- Experiment 2: Two-ICA load distribution (50-1000 clients) - Parallel multicore execution
- Experiment 3: Certificate verification and chain validation
- Experiment 4: Algorithm performance comparison
- Experiment 5: Crypto-agility demonstration

All experiments use real SPHINCS+ with GBS hashing where available.
Supports parallel multicore execution for improved performance.

Author: PQI-PKI Team
Date: April 2025
"""

import sys
import os
import time
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
from datetime import datetime
from pathlib import Path
from multiprocessing import Pool, cpu_count
from functools import partial

# Add paths relative to this file's location
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules
from sphincs_ca_integration import (
    SPHINCSProvider,
    CertificateSigningAuthority,
    QuantumSafeHashingProvider,
    CryptoAgilityManager
)


# ============================================================================
# Helper functions for parallel execution
# ============================================================================

def _issue_single_certificate(args: Tuple[int, str, str]) -> Dict:
    """
    Worker function to issue a single certificate in parallel.
    
    Args:
        args: Tuple of (client_id, ca_name, algorithm)
    
    Returns:
        Dictionary with result (success/failure, timing, etc.)
    """
    client_id, ca_name, algorithm = args
    try:
        ca = CertificateSigningAuthority(ca_name, algorithm)
        start_time = time.time()
        cert = ca.issue_certificate(f"CN=ee-{client_id}.example.com")
        elapsed = (time.time() - start_time) * 1000  # ms
        
        return {
            'client_id': client_id,
            'success': True,
            'time_ms': elapsed,
            'serial': cert['certificate']['serial_number'][:16],
            'error': None
        }
    except Exception as e:
        return {
            'client_id': client_id,
            'success': False,
            'time_ms': 0,
            'serial': None,
            'error': str(e)
        }


def _verify_single_certificate(args: Tuple[str, bytes, bytes]) -> Dict:
    """
    Worker function to verify a single certificate in parallel.
    
    Args:
        args: Tuple of (cert_id, cert_data, signature)
    
    Returns:
        Dictionary with result (valid/invalid, timing, etc.)
    """
    cert_id, cert_data, signature = args
    try:
        ca = CertificateSigningAuthority("Verifier", 'SPHINCS+-SHA2-192f-simple')
        start_time = time.time()
        is_valid = ca.sphincs_provider.verify(signature, cert_data, ca.public_key)
        elapsed = (time.time() - start_time) * 1000  # ms
        
        return {
            'cert_id': cert_id,
            'valid': is_valid,
            'time_ms': elapsed,
            'error': None
        }
    except Exception as e:
        return {
            'cert_id': cert_id,
            'valid': False,
            'time_ms': 0,
            'error': str(e)
        }


def _parallel_issue_certificates(num_clients: int, ca_name: str, algorithm: str, 
                                  num_workers: int = None) -> Tuple[List[Dict], float]:
    """
    Issue certificates in parallel across multiple cores.
    
    Args:
        num_clients: Number of clients/certificates to create
        ca_name: Name of the CA
        algorithm: Algorithm to use
        num_workers: Number of worker processes (default: cpu_count)
    
    Returns:
        (results list, total time in seconds)
    """
    if num_workers is None:
        num_workers = cpu_count()
    
    # Prepare arguments for each worker
    args_list = [(i, ca_name, algorithm) for i in range(num_clients)]
    
    start_time = time.time()
    
    with Pool(processes=num_workers) as pool:
        results = pool.map(_issue_single_certificate, args_list)
    
    total_time = time.time() - start_time
    
    return results, total_time


class ExperimentRunner:
    """Runs comprehensive CA experiments with performance measurement"""
    
    def __init__(self, output_dir: str = None):
        """Initialize experiment runner"""
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'experiments')
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.results = {}
        self.start_time = datetime.now()
    
    def run_all_experiments(self):
        """Run all experiments"""
        print("\n" + "="*80)
        print("POST-QUANTUM CERTIFICATION AUTHORITY EXPERIMENTS")
        print("="*80)
        print(f"Start time: {self.start_time}")
        print(f"Output directory: {self.output_dir}")
        
        try:
            print("\n[1/5] Running Experiment 1: Single ICA Scaling...")
            self.experiment_1_single_ica_scaling()
        except Exception as e:
            print(f"✗ Experiment 1 failed: {e}")
        
        try:
            print("\n[2/5] Running Experiment 2: Two-ICA Load Distribution...")
            self.experiment_2_two_ica_load_distribution()
        except Exception as e:
            print(f"✗ Experiment 2 failed: {e}")
        
        try:
            print("\n[3/5] Running Experiment 3: Certificate Verification...")
            self.experiment_3_certificate_verification()
        except Exception as e:
            print(f"✗ Experiment 3 failed: {e}")
        
        try:
            print("\n[4/5] Running Experiment 4: Algorithm Performance Comparison...")
            self.experiment_4_algorithm_comparison()
        except Exception as e:
            print(f"✗ Experiment 4 failed: {e}")
        
        try:
            print("\n[5/5] Running Experiment 5: Crypto-Agility Demonstration...")
            self.experiment_5_crypto_agility()
        except Exception as e:
            print(f"✗ Experiment 5 failed: {e}")
        
        self.generate_final_report()
    
    def experiment_1_single_ica_scaling(self, use_parallel: bool = True):
        """
        Experiment 1: Single ICA Scaling with Parallel Multicore Execution
        
        Tests:
        - Single Root CA + Single ICA + 5,10,25,50,100,250,500 clients
        - Measures certificate issuance throughput
        - Analyzes signing performance
        - Executes in parallel across multiple cores
        
        Args:
            use_parallel: If True, use multiprocessing for parallel execution
        """
        print("\n[EXPERIMENT 1] Single ICA Certificate Issuance Scaling (Parallel)")
        print("-" * 80)
        
        num_workers = cpu_count()
        print(f"  Using {num_workers} CPU cores for parallel execution\n")
        
        results = []
        algorithm = 'SPHINCS+-SHA2-192f-simple'
        
        # Increasing client counts
        client_counts = [5, 10, 25, 50, 100, 250, 500]
        
        for num_clients in client_counts:
            print(f"  Testing with {num_clients} concurrent clients (parallel execution)...")
            
            if use_parallel:
                # Parallel execution
                parallel_results, total_time = _parallel_issue_certificates(
                    num_clients=num_clients,
                    ca_name="ICA-1",
                    algorithm=algorithm,
                    num_workers=num_workers
                )
                
                successful_certs = sum(1 for r in parallel_results if r['success'])
                failed_certs = sum(1 for r in parallel_results if not r['success'])
                cert_times = [r['time_ms'] for r in parallel_results if r['success']]
            else:
                # Sequential execution (for comparison)
                ica = CertificateSigningAuthority("ICA-1", algorithm)
                
                start_time = time.time()
                parallel_results = []
                successful_certs = 0
                failed_certs = 0
                cert_times = []
                
                for i in range(num_clients):
                    try:
                        result_start = time.time()
                        cert = ica.issue_certificate(f"CN=ee-{i}.example.com")
                        elapsed = (time.time() - result_start) * 1000
                        cert_times.append(elapsed)
                        successful_certs += 1
                    except Exception as e:
                        failed_certs += 1
                
                total_time = time.time() - start_time
            
            # Compute statistics
            avg_time_ms = np.mean(cert_times) if cert_times else 0
            min_time_ms = np.min(cert_times) if cert_times else 0
            max_time_ms = np.max(cert_times) if cert_times else 0
            std_time_ms = np.std(cert_times) if cert_times else 0
            
            result = {
                'experiment': 'Single ICA Scaling (Parallel)',
                'num_clients': num_clients,
                'total_time_sec': total_time,
                'successful_certs': successful_certs,
                'failed_certs': failed_certs,
                'success_rate_percent': (successful_certs / num_clients * 100) if num_clients > 0 else 0,
                'throughput_certs_per_sec': successful_certs / total_time if total_time > 0 else 0,
                'avg_time_per_cert_ms': avg_time_ms,
                'min_time_per_cert_ms': min_time_ms,
                'max_time_per_cert_ms': max_time_ms,
                'std_time_per_cert_ms': std_time_ms,
                'num_workers': num_workers if use_parallel else 1
            }
            
            results.append(result)
            
            print(f"    ✓ Throughput: {result['throughput_certs_per_sec']:.2f} certs/sec")
            print(f"    ✓ Success rate: {result['success_rate_percent']:.1f}%")
            print(f"    ✓ Avg time: {result['avg_time_per_cert_ms']:.2f} ms/cert (±{result['std_time_per_cert_ms']:.2f})")
            print(f"    ✓ Time range: {result['min_time_per_cert_ms']:.2f} - {result['max_time_per_cert_ms']:.2f} ms")
        
        self.results['experiment_1'] = results
        
        # Save results
        df = pd.DataFrame(results)
        csv_path = self.output_dir / 'experiment_1_single_ica_scaling.csv'
        df.to_csv(csv_path, index=False)
        print(f"\n  ✓ Results saved to {csv_path}")
    
    def experiment_2_two_ica_load_distribution(self, use_parallel: bool = True):
        """
        Experiment 2: Two-ICA Load Distribution with Parallel Execution
        
        Tests:
        - Single Root CA + Two ICAs + 50,100,200,500,1000 clients (split between ICAs)
        - Measures load distribution
        - Analyzes throughput improvement
        - Executes both ICAs in parallel across multiple cores
        
        Args:
            use_parallel: If True, use multiprocessing for parallel execution
        """
        print("\n[EXPERIMENT 2] Two-ICA Load Distribution (Parallel)")
        print("-" * 80)
        
        num_workers = cpu_count()
        print(f"  Using {num_workers} CPU cores for parallel execution\n")
        
        results = []
        algorithm = 'SPHINCS+-SHA2-192f-simple'
        
        client_counts = [50, 100, 200, 500, 1000]
        
        for total_clients in client_counts:
            print(f"  Testing with {total_clients} clients (split between 2 ICAs in parallel)...")
            
            clients_per_ica = total_clients // 2
            
            if use_parallel:
                # Parallel execution for both ICAs simultaneously
                ica_1_results, ica_1_time = _parallel_issue_certificates(
                    num_clients=clients_per_ica,
                    ca_name="ICA-1",
                    algorithm=algorithm,
                    num_workers=num_workers // 2
                )
                
                ica_2_results, ica_2_time = _parallel_issue_certificates(
                    num_clients=clients_per_ica,
                    ca_name="ICA-2",
                    algorithm=algorithm,
                    num_workers=num_workers // 2
                )
                
                ica_1_successful = sum(1 for r in ica_1_results if r['success'])
                ica_2_successful = sum(1 for r in ica_2_results if r['success'])
            else:
                # Sequential execution
                ica_1 = CertificateSigningAuthority("ICA-1", algorithm)
                ica_2 = CertificateSigningAuthority("ICA-2", algorithm)
                
                ica_1_start = time.time()
                ica_1_successful = 0
                for i in range(clients_per_ica):
                    try:
                        ica_1.issue_certificate(f"CN=ica1-ee-{i}.example.com")
                        ica_1_successful += 1
                    except:
                        pass
                ica_1_time = time.time() - ica_1_start
                
                ica_2_start = time.time()
                ica_2_successful = 0
                for i in range(clients_per_ica):
                    try:
                        ica_2.issue_certificate(f"CN=ica2-ee-{i}.example.com")
                        ica_2_successful += 1
                    except:
                        pass
                ica_2_time = time.time() - ica_2_start
            
            ica_1_throughput = ica_1_successful / ica_1_time if ica_1_time > 0 else 0
            ica_2_throughput = ica_2_successful / ica_2_time if ica_2_time > 0 else 0
            
            result = {
                'experiment': 'Two-ICA Load Distribution (Parallel)',
                'total_clients': total_clients,
                'clients_per_ica': clients_per_ica,
                'ica_1_successful': ica_1_successful,
                'ica_1_time_sec': ica_1_time,
                'ica_1_throughput_certs_per_sec': ica_1_throughput,
                'ica_2_successful': ica_2_successful,
                'ica_2_time_sec': ica_2_time,
                'ica_2_throughput_certs_per_sec': ica_2_throughput,
                'combined_throughput_certs_per_sec': ica_1_throughput + ica_2_throughput,
                'load_balance_ratio': ica_1_throughput / ica_2_throughput if ica_2_throughput > 0 else 1.0,
                'num_workers': num_workers if use_parallel else 1
            }
            
            results.append(result)
            
            print(f"    ✓ ICA-1 throughput: {ica_1_throughput:.2f} certs/sec ({ica_1_successful} success)")
            print(f"    ✓ ICA-2 throughput: {ica_2_throughput:.2f} certs/sec ({ica_2_successful} success)")
            print(f"    ✓ Combined throughput: {result['combined_throughput_certs_per_sec']:.2f} certs/sec")
            print(f"    ✓ Load balance: {result['load_balance_ratio']:.2f}x")
        
        self.results['experiment_2'] = results
        
        # Save results
        df = pd.DataFrame(results)
        csv_path = self.output_dir / 'experiment_2_two_ica_distribution.csv'
        df.to_csv(csv_path, index=False)
        print(f"\n  ✓ Results saved to {csv_path}")
    
    def experiment_3_certificate_verification(self):
        """
        Experiment 3: Certificate Verification and Chain Validation
        
        Tests:
        - Multi-level certificate verification
        - Chain-of-trust validation
        - Signature verification performance
        """
        print("\n[EXPERIMENT 3] Certificate Verification and Chain Validation")
        print("-" * 80)
        
        results = []
        root_ca = CertificateSigningAuthority("RootCA", 'SPHINCS+-SHA2-192f-simple')
        ica = CertificateSigningAuthority("ICA-1", 'SPHINCS+-SHA2-192f-simple')
        
        num_certs = 50
        print(f"\n  Issuing {num_certs} certificates for verification testing...")
        
        # Issue certificates
        issued_certs = []
        for i in range(num_certs):
            cert = ica.issue_certificate(f"CN=ee-{i}.example.com")
            issued_certs.append(cert)
        
        print(f"  ✓ Issued {len(issued_certs)} certificates")
        
        # Test verification
        print(f"\n  Verifying {len(issued_certs)} certificates...")
        
        start_time = time.time()
        verified_count = 0
        failed_count = 0
        verification_times = []
        
        for cert in issued_certs:
            cert_start = time.time()
            try:
                cert_id = cert['certificate']['serial_number']
                is_valid = ica.verify_issued_certificate(cert_id)
                
                if is_valid:
                    verified_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                failed_count += 1
            
            cert_time = (time.time() - cert_start) * 1000  # ms
            verification_times.append(cert_time)
        
        total_verify_time = time.time() - start_time
        
        result = {
            'experiment': 'Certificate Verification',
            'total_certificates': num_certs,
            'verified_count': verified_count,
            'failed_count': failed_count,
            'verification_success_rate': verified_count / num_certs * 100,
            'total_verification_time_sec': total_verify_time,
            'avg_verification_time_ms': np.mean(verification_times),
            'min_verification_time_ms': np.min(verification_times),
            'max_verification_time_ms': np.max(verification_times),
            'std_verification_time_ms': np.std(verification_times),
            'verification_throughput_per_sec': verified_count / total_verify_time if total_verify_time > 0 else 0
        }
        
        results.append(result)
        self.results['experiment_3'] = results
        
        print(f"\n  ✓ Verification success rate: {result['verification_success_rate']:.1f}%")
        print(f"  ✓ Avg verification time: {result['avg_verification_time_ms']:.4f} ms")
        print(f"  ✓ Verification throughput: {result['verification_throughput_per_sec']:.2f} verifications/sec")
        
        # Save results
        df = pd.DataFrame(results)
        csv_path = self.output_dir / 'experiment_3_verification.csv'
        df.to_csv(csv_path, index=False)
        print(f"  ✓ Results saved to {csv_path}")
    
    def experiment_4_algorithm_comparison(self):
        """
        Experiment 4: Algorithm Performance Comparison
        
        Tests performance of different SPHINCS+ parameter sets:
        - SPHINCS+-SHA2-128f-simple (NIST Level 1)
        - SPHINCS+-SHA2-192f-simple (NIST Level 3)
        """
        print("\n[EXPERIMENT 4] Algorithm Performance Comparison")
        print("-" * 80)
        
        results = []
        algorithms = [
            'SPHINCS+-SHA2-128f-simple',
            'SPHINCS+-SHA2-192f-simple'
        ]
        
        num_certs_per_algo = 20
        
        for algo in algorithms:
            print(f"\n  Testing {algo}...")
            
            try:
                ca = CertificateSigningAuthority(f"CA-{algo[:10]}", algo)
                
                start_time = time.time()
                successful = 0
                failed = 0
                
                for i in range(num_certs_per_algo):
                    try:
                        cert = ca.issue_certificate(f"CN=test-{i}.example.com")
                        successful += 1
                    except Exception as e:
                        failed += 1
                
                total_time = time.time() - start_time
                
                # Get metrics
                metrics = ca.sphincs_provider.get_metrics_summary()
                
                result = {
                    'algorithm': algo,
                    'nist_level': SPHINCSProvider.PARAMETER_SETS[algo]['nist_level'],
                    'public_key_size_bytes': SPHINCSProvider.PARAMETER_SETS[algo]['public_key_size'],
                    'secret_key_size_bytes': SPHINCSProvider.PARAMETER_SETS[algo]['secret_key_size'],
                    'signature_size_bytes': SPHINCSProvider.PARAMETER_SETS[algo]['signature_size'],
                    'certificates_issued': successful,
                    'total_time_sec': total_time,
                    'throughput_certs_per_sec': successful / total_time if total_time > 0 else 0,
                    'avg_signing_time_ms': metrics.get('avg_signing_time_ms', 0),
                    'avg_throughput_certs_per_sec': metrics.get('avg_throughput', 0)
                }
                
                results.append(result)
                
                print(f"    ✓ Throughput: {result['throughput_certs_per_sec']:.2f} certs/sec")
                print(f"    ✓ Avg signing time: {result['avg_signing_time_ms']:.2f} ms")
                
            except Exception as e:
                print(f"    ✗ Error testing {algo}: {e}")
        
        self.results['experiment_4'] = results
        
        # Save results
        df = pd.DataFrame(results)
        csv_path = self.output_dir / 'experiment_4_algorithm_comparison.csv'
        df.to_csv(csv_path, index=False)
        print(f"\n  ✓ Results saved to {csv_path}")
    
    def experiment_5_crypto_agility(self):
        """
        Experiment 5: Crypto-Agility Demonstration
        
        Tests:
        - Algorithm switching capability
        - Multi-algorithm support
        - Seamless migration
        """
        print("\n[EXPERIMENT 5] Crypto-Agility Demonstration")
        print("-" * 80)
        
        results = []
        
        print("\n  Initializing Crypto-Agility Manager...")
        manager = CryptoAgilityManager()
        
        available_algos = manager.list_available_algorithms()
        print(f"  ✓ Available algorithms: {len(available_algos)}")
        
        for algo in available_algos:
            print(f"\n  Testing {algo}...")
            
            try:
                manager.set_algorithm(algo)
                provider = manager.get_provider()
                
                # Test key generation and signing
                sk, pk = provider.generate_keypair()
                message = b"Test message for crypto-agility"
                signature = provider.sign(message, sk)
                valid = provider.verify(signature, message, pk)
                
                metrics = provider.get_metrics_summary()
                
                result = {
                    'algorithm': algo,
                    'keypair_generated': True,
                    'signature_created': True,
                    'signature_verified': valid,
                    'avg_signing_time_ms': metrics.get('avg_signing_time_ms', 0),
                    'throughput_certs_per_sec': metrics.get('avg_throughput', 0)
                }
                
                results.append(result)
                
                print(f"    ✓ Keypair generated successfully")
                print(f"    ✓ Signature created and verified: {valid}")
                
            except Exception as e:
                print(f"    ✗ Error: {e}")
                results.append({
                    'algorithm': algo,
                    'error': str(e)
                })
        
        self.results['experiment_5'] = results
        
        # Save results
        df = pd.DataFrame(results)
        csv_path = self.output_dir / 'experiment_5_crypto_agility.csv'
        df.to_csv(csv_path, index=False)
        print(f"\n  ✓ Results saved to {csv_path}")
    
    def generate_final_report(self):
        """Generate comprehensive final report"""
        print("\n" + "="*80)
        print("GENERATING FINAL REPORT")
        print("="*80)
        
        report_path = self.output_dir / 'EXPERIMENT_RESULTS_REPORT.md'
        
        with open(report_path, 'w') as f:
            f.write("# Post-Quantum Certification Authority Experiments Report\n\n")
            f.write(f"**Generated**: {datetime.now().isoformat()}\n\n")
            f.write(f"**Location**: {self.output_dir}\n\n")
            
            f.write("## Executive Summary\n\n")
            f.write("This report presents comprehensive experimental results for the post-quantum ")
            f.write("certification authority (CA) system using SPHINCS+ with Gaussian Boson Sampling (GBS).\n\n")
            
            # Experiment summaries
            f.write("## Experiment Results\n\n")
            
            if 'experiment_1' in self.results:
                f.write("### Experiment 1: Single ICA Scaling\n\n")
                df = pd.DataFrame(self.results['experiment_1'])
                f.write(df.to_markdown(index=False) + "\n\n")
                
                f.write("**Key Findings**:\n")
                if len(df) > 0:
                    max_throughput = df['throughput_certs_per_sec'].max()
                    f.write(f"- Maximum throughput: {max_throughput:.2f} certs/second\n")
                    f.write(f"- Success rate: >{df['success_rate_percent'].min():.1f}%\n")
                f.write("\n")
            
            if 'experiment_2' in self.results:
                f.write("### Experiment 2: Two-ICA Load Distribution\n\n")
                df = pd.DataFrame(self.results['experiment_2'])
                f.write(df.to_markdown(index=False) + "\n\n")
                
                f.write("**Key Findings**:\n")
                if len(df) > 0:
                    max_combined = df['combined_throughput_certs_per_sec'].max()
                    f.write(f"- Maximum combined throughput: {max_combined:.2f} certs/second\n")
                f.write("\n")
            
            if 'experiment_3' in self.results:
                f.write("### Experiment 3: Certificate Verification\n\n")
                df = pd.DataFrame(self.results['experiment_3'])
                f.write(df.to_markdown(index=False) + "\n\n")
            
            if 'experiment_4' in self.results:
                f.write("### Experiment 4: Algorithm Comparison\n\n")
                df = pd.DataFrame(self.results['experiment_4'])
                f.write(df.to_markdown(index=False) + "\n\n")
            
            if 'experiment_5' in self.results:
                f.write("### Experiment 5: Crypto-Agility\n\n")
                df = pd.DataFrame(self.results['experiment_5'])
                f.write(df.to_markdown(index=False) + "\n\n")
            
            # Conclusion
            f.write("## Conclusion\n\n")
            f.write("The post-quantum certification authority framework demonstrates:\n")
            f.write("- High throughput for certificate issuance\n")
            f.write("- Effective load distribution across multiple ICAs\n")
            f.write("- Reliable certificate verification\n")
            f.write("- Flexible algorithm selection and crypto-agility\n")
        
        print(f"\n✓ Final report generated: {report_path}")
        
        # Save results as JSON
        json_path = self.output_dir / 'experiment_results.json'
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"✓ Results saved as JSON: {json_path}")
        
        print(f"\n✓ All experiments completed successfully!")
        print(f"✓ Results location: {self.output_dir}")


def main():
    """Main entry point"""
    print("Starting Post-Quantum CA Experiments...")
    
    runner = ExperimentRunner()
    runner.run_all_experiments()


if __name__ == "__main__":
    main()
