# -*- coding: utf-8 -*-

""" GBS HASH"""

import strawberryfields as sf # Import the core library for photonic quantum computing
from strawberryfields import ops # Import operations like Squeezing and Beamsplitters
import numpy as np # Import numpy for linear algebra and random sampling
import itertools # Import itertools to help with Wick's theorem expansions

class GBS:
    def __init__(self):
        self._message_bits = bytes()   # stores bits as '0'/'1'
        self.__len__ = 0            # length of the bitstring

    # def update(self, value, bit_length=None):
    #     """
    #     Append bits to the buffer.

    #     value:
    #       - int  → requires bit_length
    #       - str  → must be '0'/'1' string
    #       - bytes → appended byte-wise
    #     """
    #     if isinstance(value, str):
    #         if not set(value) <= {"0", "1"}:
    #             raise ValueError("Bit string must contain only '0' and '1'")
    #         self._message_bits += value

    #     elif isinstance(value, int):
    #         if bit_length is None:
    #             raise ValueError("bit_length required for int")
    #         bits = format(value, f"0{bit_length}b")
    #         self._message_bits += bits

    #     elif isinstance(value, (bytes, bytearray)):
    #         for b in value:
    #             self._message_bits += f"{b:08b}"

    #     else:
    #         raise TypeError("Unsupported type")
        
    def update(self, data: bytes):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            data = bytes(data, "utf-8")

        self._message_bits += data
        self.__len__ += len(data) * 8

        while len(self._message_bits) >= 64:  # 512 bits
            block = self._message_bits[:64]
            self._message_bits = self._message_bits[64:]

    def bits(self):
        return self._message_bits

    def iter_bits_little_endian(self, data: bytes, N: int):
        idx = 0
        for byte in data:
            for i in range(8):
                if idx >= N:
                    return
                yield idx, (byte >> i) & 1
                idx += 1

    def get_photonic_hash(self, depth=4, k=2): # Main function for hashing a bitstring
        # print(f"Computing photonic hash for message: {self._message_bits} with depth={depth}, k={k}")
        N = self.__len__ # N modes correspond to the N-bit input message
        eng = sf.Engine("gaussian") # Initialize the Gaussian backend engine for simulation
        prog = sf.Program(N) # Create a quantum program with N modes

        # Publicly shared random parameters for the interferometer (as per blockchain protocol)
        np.random.seed(42) # Set seed to ensure the 'random' interferometer is consistent
        phis = np.random.uniform(0, 2 * np.pi, (depth, N // 2)) # Sample random phases from U(0, 2pi)
        thetas = np.random.normal(np.pi / 4, np.pi / 16, (depth, N // 2)) # Sample mixing angles from N(pi/4, pi/16)

        with prog.context as q: # Define the circuit construction block
            # 1. State Preparation: Embed the message into squeezed vacuum (Eq. 4)
            # for j in range(N): # Iterate through each mode to apply input bits
            #     r_val = float(self._message_bits[j]) # Use bit value as squeezing parameter (r=1 or r=0)
            #     if r_val > 0: # Only apply Sgate if the input bit is 1 (r=0 is vacuum)
            #         ops.Sgate(r_val) | q[j] # Apply Squeezing operator to the j-th mode

            for j, bit in self.iter_bits_little_endian(self._message_bits, N): # Iterate through each mode to apply input bits
                if bit: # Use bit value as squeezing parameter (r=1 or r=0), Only apply Sgate if the input bit is 1 (r=0 is vacuum)
                    ops.Sgate(1.0) | q[j] # Apply Squeezing operator to the j-th mode

            # 2. Interferometer: Brickwork structure with periodic boundaries (Eq. 1-3)
            for l in range(depth): # Iterate through layers of the interferometer
                for j_idx in range(N // 2): # Iterate through pairs of modes
                    if l % 2 == 0: # Even layers: connect neighboring pairs (0,1), (2,3)...
                        m1, m2 = 2 * j_idx, 2 * j_idx + 1 # Identify mode indices for even layer
                    else: # Odd layers: connect shifted pairs (1,2), (3,0)...
                        m1, m2 = 2 * j_idx + 1, (2 * j_idx + 2) % N # Use modulo N for periodic wrap-around

                    theta, phi = thetas[l, j_idx], phis[l, j_idx] # Retrieve the random BS parameters
                    # Construct the custom Unitary matrix for the paper's specific BS definition (Eq. 3)
                    u_bs = np.array([
                        [np.cos(theta), np.exp(-1j * phi) * np.sin(theta)],
                        [-np.exp(1j * phi) * np.sin(theta), np.cos(theta)]
                    ]) # This matrix defines the rotation and phase shift of the beamsplitter
                    ops.Interferometer(u_bs) | (q[m1], q[m2]) # Apply the BS unitary to the mode pair

        # Run the simulation on the Gaussian backend to get the final state
        result = eng.run(prog) # Execute the quantum circuit
        state = result.state # Extract the Gaussian state object (covariance matrix)

        hash_bits = "" # Initialize the string to store the resulting hash bits
        # 3. Correlation Measurement and Post-processing (Eq. 7-9)
        for j in range(N): # Loop to compute one bit of hash for each mode
            target_modes = [j, (j + 1) % N, (j + 2) % N] # Nearest-neighbor triplets with periodic index
            # Compute the expectation value <nj * n(j+1) * n(j+2)> from the covariance matrix
            mu_j = self.compute_three_mode_corr(state, target_modes) # Use Wick's theorem for Gaussian moments
            # Extract the k-th decimal bit as specified in the hash protocol (Eq. 9)
            bit = int(np.floor(10**k * mu_j)) % 2 # Take floor(10^k * mu) mod 2 to get the bit
            hash_bits += str(bit) # Concatenate the bit to the final hash string

        return int(hash_bits,2).to_bytes((len(hash_bits) + 7) // 8, byteorder='big') # Return the completed N-bit hash value

    def compute_three_mode_corr(self, state, modes):
        # 1. SORT the modes to satisfy Strawberry Fields requirements
        sorted_modes = sorted(list(set(modes)))

        # Check if we actually have 3 distinct modes (N must be > 2)
        if len(sorted_modes) < 3:
            return 0.0

        # 2. Get the reduced Gaussian state for the sorted modes
        # This returns the 6x6 covariance matrix V
        _, V = state.reduced_gaussian(sorted_modes)

        # 3. Map the original requested modes to their new indices in the 6x6 matrix
        # If modes were [7, 0, 1], sorted_modes is [0, 1, 7]
        # '0' is now at index 0, '1' at index 1, '7' at index 2
        mode_map = {actual_mode: i for i, actual_mode in enumerate(sorted_modes)}
        m_indices = [mode_map[m] for m in modes]

        # Inner helper for Wick's pairings
        def wick(indices):
            if not indices: return 1.0
            res, first = 0, indices[0]
            for i in range(1, len(indices)):
                res += V[first, indices[i]] * wick([x for x in indices if x != first and x != indices[i]])
            return res

        # 4. Compute moments using the mapped indices
        # We use m_indices to ensure we are looking at the correct spots in the 6x6 matrix
        term_6th = 0
        # i, j, k represent the three modes in the order they were requested
        for i_sub, j_sub, k_sub in [(0, 1, 2)]:
            # Convert mode indices to quadrature indices (2*m for q, 2*m+1 for p)
            m1, m2, m3 = m_indices[0], m_indices[1], m_indices[2]
            for qp1, qp2, qp3 in itertools.product([2*m1, 2*m1+1], [2*m2, 2*m2+1], [2*m3, 2*m3+1]):
                term_6th += wick([qp1, qp1, qp2, qp2, qp3, qp3])

        # Repeat logic for 4th and 2nd order terms...
        # (The rest of the expansion remains the same, just ensure you use m_indices)

        # Simplified calculation for mu_j using the variances of the specific modes
        # mu_j = <n1 n2 n3>
        # For a Gaussian state with zero mean, <ni> = (V_qi_qi + V_pi_pi - 1)/2
        # (Note: scaling depends on hbar convention, SF uses hbar=2 by default)

        # To keep it robust, let's use the mapped indices for the final mu calculation:
        mu = term_6th # This is a placeholder for the full expansion sum
        return mu / 64.0

# --- Example Execution ---
# import secrets, hmac, time

# g = GBS()
# g.update(format(secrets.randbits(256), '0256b'))
# # print(bits)
# # input_message = "11010010" # Example 8-bit message to hash

# start = time.perf_counter()
# a = g.get_photonic_hash(depth=8, k=4) # Compute hash with depth 6 and precision k=4
# end = time.perf_counter()

# b = g.get_photonic_hash(depth=8, k=4) # Compute hash with depth 6 and precision k=4
# # photonic_hash = get_photonic_hash(input_message, depth=8, k=4) # Compute hash with depth 6 and precision k=4
# print(f"Input Message: {g._message_bits}") # Print original message
# print(f"Photonic Hash: {a}") # Print result of the photonic hashing algorithm
# print(hmac.compare_digest(a, b))  # True if hashes match
# print(f"Execution time: {end - start:.6f} seconds")

#----------------------------------------------------------------------------------------------------------------------

# import strawberryfields as sf
# from strawberryfields import ops
# import numpy as np


# def get_photonic_hash(message_bits, depth=4, k=2, shots=5000, cutoff=7):
#     """GBS-based hash as defined in the paper, using sampling of photon numbers."""
#     N = len(message_bits)

#     # Fock backend with cutoff for PNR sampling
#     eng = sf.Engine("fock", backend_options={"cutoff_dim": cutoff})
#     prog = sf.Program(N)

#     # Public random interferometer parameters (same as paper)
#     np.random.seed(42)
#     phis = np.random.uniform(0, 2 * np.pi, (depth, N // 2))
#     thetas = np.random.normal(np.pi / 4, np.pi / 16, (depth, N // 2))

#     with prog.context as q:
#         # 1. Input encoding: |Ψ_in(b)> = ∏_j S_j(b_j)|0>
#         for j in range(N):
#             r_val = float(message_bits[j])
#             if r_val > 0:
#                 ops.Sgate(r_val) | q[j]

#         # 2. Random interferometer in brickwork pattern with periodic boundary
#         for l in range(depth):
#             for j_idx in range(N // 2):
#                 if l % 2 == 0:
#                     m1, m2 = 2 * j_idx, 2 * j_idx + 1
#                 else:
#                     m1, m2 = 2 * j_idx + 1, (2 * j_idx + 2) % N

#                 theta, phi = thetas[l, j_idx], phis[l, j_idx]
#                 u_bs = np.array(
#                     [
#                         [np.cos(theta), np.exp(-1j * phi) * np.sin(theta)],
#                         [-np.exp(1j * phi) * np.sin(theta), np.cos(theta)],
#                     ]
#                 )
#                 ops.Interferometer(u_bs) | (q[m1], q[m2])

#         # 3. PNR measurement on all modes
#         ops.MeasureFock() | q

#     # Run with many shots to estimate correlators
#     result = eng.run(prog, shots=shots)
#     # samples: shape (shots, N), entries = photon numbers n_j
#     samples = result.samples

#     # Estimate µ_j = <n_j n_{j+1} n_{j+2}>
#     mus = []
#     for j in range(N):
#         j1 = j
#         j2 = (j + 1) % N
#         j3 = (j + 2) % N
#         n1 = samples[:, j1]
#         n2 = samples[:, j2]
#         n3 = samples[:, j3]
#         mu_j = np.mean(n1 * n2 * n3)
#         mus.append(mu_j)

#     # Convert µ_j to bits via k-th decimal parity
#     hash_bits = ""
#     for mu_j in mus:
#         bit = int(np.floor(10 ** k * mu_j)) % 2
#         hash_bits += str(bit)

#     return hash_bits


# # Example usage:
# input_message = "11010010"
# h = get_photonic_hash(input_message, depth=6, k=4, shots=20000, cutoff=9)
# print(h)
