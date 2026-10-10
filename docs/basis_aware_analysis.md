# Cryptographic Analysis: Basis-Aware Adversary on Deterministic Basis Schedule

**Target System:** Teleportation-Based Symmetric-Key Signature-Style Authentication Scheme  
**Repository:** `Naman-Vasudev/QKD`  
**Date:** October 2026  
**Document Status:** Technical Analysis Note  

---

## 1. Context and Objective

In this simulation testbed, a classical message $M$ is authenticated using a sequence of Pauli eigenstates teleported from Alice to Bob. The protocol defines:
1. A canonical bound payload $P = M \parallel \mathrm{signer\_id} \parallel N \parallel \mathrm{counter} \parallel \mathrm{timestamp}$.
2. A 256-bit cryptographic digest $D = \text{SHA-256}(P) = (d_0, d_1, \dots, d_{255})$.
3. A shared secret key $K = (K_0, K_1, \dots, K_{255}) \in \{0, 1\}^{256}$.
4. Encoded bits $b_i = d_i \oplus K_i$ for each $i \in \{0, \dots, 255\}$.
5. A deterministic public basis schedule:
   $$B_i = \begin{cases} Z & \text{if } i \equiv 0 \pmod 3 \\ X & \text{if } i \equiv 1 \pmod 3 \\ Y & \text{if } i \equiv 2 \pmod 3 \end{cases}$$
6. State preparation: for index $i$, Alice prepares the Pauli eigenstate of basis $B_i$ corresponding to eigenvalue $+1$ if $b_i = 0$ and $-1$ if $b_i = 1$.
7. Transmission via 3-qubit teleportation: Alice performs a Bell measurement on $(q_0, q_1)$, broadcasts the two measurement bits $(c_0, c_1)$ over an authenticated public classical channel, and Bob applies Pauli corrections $X^{c_1} Z^{c_0}$ to $q_2$.
8. Verification: Bob measures $q_2$ in basis $B_i$, checking for eigenvalue agreement.

We evaluate whether an adversary Eve, who knows the public basis schedule, observes the public message $M$ (and hence digest $D$), and observes the classical teleportation correction bits $(c_0, c_1)$, can recover secret key bits $K_i$.

---

## 2. Adversary Model and Assumptions

### Capabilities
- **Message Access:** Eve knows the message $M$, nonce $N$, and all public parameters, and can compute $d_i = \text{SHA-256}(P)_i$.
- **Schedule Knowledge:** Eve knows the basis assignment rule $B_i = i \pmod 3$ for all positions.
- **Classical Channel Eavesdropping:** Eve passively observes all classical bits transmitted between Alice and Bob, including teleportation feedforward bits $(c_0, c_1)_i$.
- **Quantum Channel Access:** Depending on the scenario:
  - *Scenario 1 (Passive Classical Eavesdropping Only):* Eve observes classical messages and correction bits, but does NOT intercept quantum states.
  - *Scenario 2 (Active Individual-Qubit Interception with Basis Awareness):* Eve intercepts individual qubits on the quantum transmission channel before Bob's readout.

---

## 3. Step-by-Step Analysis

### Scenario 1: Passive Observation of Classical Bits $(c_0, c_1)$ Alone

In standard 3-qubit quantum teleportation:
- Let the input state prepared on qubit $q_0$ be $|\psi_i\rangle = \alpha |0\rangle + \beta |1\rangle$, where $|\psi_i\rangle$ is an eigenstate of $B_i$.
- The entangled resource on $(q_1, q_2)$ is $|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$.
- The joint 3-qubit state expands in the Bell basis of $(q_0, q_1)$ as:
  $$|\psi_i\rangle_{0} \otimes |\Phi^+\rangle_{12} = \frac{1}{2} \sum_{c_0, c_1 \in \{0, 1\}} |\text{Bell}_{c_0, c_1}\rangle_{01} \otimes \left( X^{c_1} Z^{c_0} |\psi_i\rangle \right)_2$$
  where $|\text{Bell}_{00}\rangle = |\Phi^+\rangle$, $|\text{Bell}_{10}\rangle = |\Phi^-\rangle$, $|\text{Bell}_{01}\rangle = |\Psi^+\rangle$, $|\text{Bell}_{11}\rangle = |\Psi^-\rangle$.

Because $\{|\text{Bell}_{c_0, c_1}\rangle\}$ forms a complete orthonormal basis on $\mathcal{H}_2 \otimes \mathcal{H}_2$:
$$\operatorname{Pr}(c_0, c_1) = \operatorname{Tr}\left[ \left( |\text{Bell}_{c_0, c_1}\rangle\langle\text{Bell}_{c_0, c_1}| \otimes I \right) \rho_{\text{total}} \right] = \frac{1}{4} \left( |\alpha|^2 + |\beta|^2 \right) = \frac{1}{4}$$
for every pair $(c_0, c_1) \in \{0, 1\}^2$, regardless of $|\psi_i\rangle$.

**Result 1:** The marginal distribution of classical teleportation correction bits $(c_0, c_1)$ is strictly uniform and statistically independent of $|\psi_i\rangle$, $b_i$, and $K_i$. Therefore, observing $(c_0, c_1)$ alone over the classical channel yields zero Shannon information about the key:
$$I(K_i; c_0, c_1) = 0$$

---

### Scenario 2: Active Individual-Qubit Interception with Known Basis Schedule

Now consider an adversary Eve sitting on the quantum channel under the individual-qubit attack model (the standard model implemented in `attacks/interception.py`).

In the baseline random intercept-resend attack (`attacks/interception.py`), Eve is assumed not to know $B_i$. She guesses a basis uniformly from $\{Z, X, Y\}$. With probability $2/3$, her basis mismatches Alice's, collapsing the state into an orthogonal basis and inducing Bob to observe errors with probability $1/2$. The resulting net error rate is:
$$\left(\frac{1}{3} \times 0\right) + \left(\frac{2}{3} \times \frac{1}{2}\right) = \frac{1}{3} \approx 33.33\%$$
which the statistical detector flags with near-certainty ($> 99.99\%$ power for $n \ge 32$).

**However, the basis schedule is public and deterministic ($B_i = i \pmod 3$).**
A basis-aware adversary operates as follows:
1. For qubit index $i$, Eve queries the deterministic schedule and identifies the exact basis $B_i$.
2. Eve intercepts Alice's state qubit $q_0$ before the teleportation measurement (or intercepts Bob's qubit $q_2$ and uses $(c_0, c_1)$).
3. Eve performs a projective measurement on the intercepted qubit in basis $B_i$.
4. **State Commutation:** Because Alice prepared an eigenstate of basis $B_i$, Eve's measurement operator $M_{B_i}$ commutes with the density matrix $\rho_i = |\psi_i\rangle\langle\psi_i|$. 
5. **No Measurement Disturbance:** The projective measurement leaves the state in the exact eigenstate $|\psi_i\rangle$:
   $$\frac{P_{B_i, m} |\psi_i\rangle\langle\psi_i| P_{B_i, m}}{\operatorname{Tr}(P_{B_i, m} |\psi_i\rangle\langle\psi_i|)} = |\psi_i\rangle\langle\psi_i|$$
   There is zero basis-collapse noise.
6. **Key Extraction:** Eve's classical measurement outcome $c_{\text{eve}} \in \{0, 1\}$ directly reveals $b_i$:
   - Outcome $0$ indicates eigenvalue $+1 \implies b_i = 0$.
   - Outcome $1$ indicates eigenvalue $-1 \implies b_i = 1$.
   Since $b_i = d_i \oplus K_i$ and Eve computes $d_i = \text{SHA-256}(P)_i$, Eve computes:
   $$K'_i = b'_i \oplus d_i$$
   On an ideal channel, $K'_i = K_i$ with probability $1.0$. Eve recovers $100\%$ of the secret key bits.
7. **Zero Detection Trace:** Eve re-prepares (or passes through) the eigenstate matching her outcome. Bob receives the state, measures in basis $B_i$, and observes eigenvalue agreement with probability $1.0$ (error count $= 0$). Bob's detector observes an error rate of $0.0$, concludes the transmission is legitimate, and accepts the signature.

---

## 4. Empirical Verification

We implemented this attack in `attacks/basis_aware.py` and executed simulation runs across $n = 64$ qubits on Qiskit Aer (fixed seed):
- **Key bits extracted by Eve:** $64 / 64$ ($100.0\%$ key leakage).
- **Errors observed by Bob:** $0 / 64$ ($0.0\%$ observed error rate).
- **Detector verdict:** `threat_detected = False` (detection rate $= 0.0\%$).
- **Verifier verdict:** `ACCEPT`.

---

## 5. Cryptographic Significance & Limitations Summary

1. **Protocol Vulnerability:** The combination of a deterministic, public basis schedule with standard orthogonal Pauli eigenstates makes the scheme completely transparent to an active individual-qubit interceptor.
2. **Comparison with Standard QKD/QDS:**
   - Standard QKD (BB84/BBM92) and memoryless QDS protocols (e.g., Dunjko et al. 2014) ensure security against intercept-resend because bases are chosen **randomly and kept secret** until after quantum transmission.
   - Without basis uncertainty, the no-cloning theorem and measurement-disturbance principle provide no protection against a channel adversary measuring in the known eigenbasis.
3. **Conclusion for Cryptographers:** Under an active individual-qubit eavesdropping model, the scheme does not provide unforgeability or key confidentiality once an active adversary exploits the public schedule. The protocol's claimed unforgeability bound holds only against an adversary who cannot intercept the quantum channel, or who is artificially constrained to guess bases blindly.
