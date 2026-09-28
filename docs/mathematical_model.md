# Mathematical Model of Teleportation-Based Quantum Digital Signatures

**Deliverable 1** — Formal description of the signature protocol: Bell-state entanglement,
the quantum teleportation process, Pauli correction operations, and projective measurement
rules.

---

## Notation

| Symbol | Meaning |
|---|---|
| $M$ | Classical message payload (UTF-8 string) |
| $P$ | Session-bound payload actually hashed |
| $D = (d_0,\dots,d_{n-1})$ | SHA-256 digest bits, $n = 256$ |
| $K = (K_0,\dots,K_{n-1})$ | Pre-shared secret key bits |
| $b_i = d_i \oplus K_i$ | Encoded signature bit at position $i$ |
| $B_i \in \{Z, X, Y\}$ | Measurement basis at position $i$ |
| $\lvert\psi_i\rangle$ | Signature state at position $i$ |
| $\lambda_i \in \{+1,-1\}$ | Expected eigenvalue at position $i$ |
| $p_0$ | Calibrated baseline channel error rate |
| $\hat{e}$ | Observed verification error rate |
| $s_a, s_v$ | Acceptance and rejection thresholds |

---

## 1. Classical Preprocessing and Session Binding

The signer constructs a freshness-bound payload from the message, a cryptographically
random nonce $\nu$, a monotonic counter $c$, the signer identity $\mathrm{id}$, and a
timestamp $t$:

$$P = M \,\|\, \mathrm{id} \,\|\, \nu \,\|\, c \,\|\, t$$

$$D = \mathrm{SHA\text{-}256}(P), \qquad D \in \{0,1\}^{256}$$

The signature bits are formed by one-time-pad style masking with the secret key:

$$b_i = d_i \oplus K_i, \qquad i = 0,\dots,255$$

**Why the mask is essential.** For $K$ drawn uniformly from $\{0,1\}^{256}$, each $b_i$ is
uniform on $\{0,1\}$ and statistically independent of $D$:

$$\Pr[b_i = 0] = \Pr[d_i = K_i] = \tfrac{1}{2}$$

An adversary who knows $M$, and therefore $D$, obtains **zero** information about $b_i$.
This is the source of the protocol's information-theoretic security. SHA-256 alone is not a
signature: without $K$, any party could compute $D$ and prepare the corresponding states.

**Basis schedule.** The basis at each position is fixed by a public, deterministic rule:

$$B_i = \begin{cases}
Z & i \equiv 0 \pmod 3\\
X & i \equiv 1 \pmod 3\\
Y & i \equiv 2 \pmod 3
\end{cases}$$

The schedule is public. Secrecy resides entirely in $K$, and the schedule's purpose is to
distribute the signature across all three Pauli observables so that basis-selective
disturbances become identifiable (see §7).

---

## 2. Pauli Eigenstate Encoding

Each pair $(b_i, B_i)$ maps to one of six Pauli eigenstates with a definite eigenvalue:

| $B_i$ | $b_i = 0$ | $\lambda_i$ | $b_i = 1$ | $\lambda_i$ |
|---|---|---|---|---|
| $Z$ | $\lvert 0\rangle$ | $+1$ | $\lvert 1\rangle$ | $-1$ |
| $X$ | $\lvert +\rangle = \tfrac{1}{\sqrt2}(\lvert 0\rangle + \lvert 1\rangle)$ | $+1$ | $\lvert -\rangle = \tfrac{1}{\sqrt2}(\lvert 0\rangle - \lvert 1\rangle)$ | $-1$ |
| $Y$ | $\lvert {+i}\rangle = \tfrac{1}{\sqrt2}(\lvert 0\rangle + i\lvert 1\rangle)$ | $+1$ | $\lvert {-i}\rangle = \tfrac{1}{\sqrt2}(\lvert 0\rangle - i\lvert 1\rangle)$ | $-1$ |

Each state satisfies the eigenvalue equation

$$\sigma_{B_i} \lvert\psi_i\rangle = \lambda_i \lvert\psi_i\rangle,
\qquad \sigma_Z, \sigma_X, \sigma_Y \text{ the Pauli operators.}$$

**Preparation circuits** (from $\lvert 0\rangle$):

$$\lvert 0\rangle = I,\quad
\lvert 1\rangle = X,\quad
\lvert +\rangle = H,\quad
\lvert -\rangle = HX,\quad
\lvert {+i}\rangle = SH,\quad
\lvert {-i}\rangle = SHX$$

where $H = \tfrac{1}{\sqrt2}\begin{pmatrix}1&1\\1&-1\end{pmatrix}$ and
$S = \begin{pmatrix}1&0\\0&i\end{pmatrix}$.

---

## 3. Bell-State Entanglement

Verification transmits each $\lvert\psi_i\rangle$ by teleportation over an EPR pair. The
resource state is the Bell state

$$\lvert\Phi^+\rangle_{12} = \tfrac{1}{\sqrt2}\left(\lvert 00\rangle + \lvert 11\rangle\right)$$

prepared by $H$ on qubit 1 followed by $\mathrm{CNOT}_{1\to2}$:

$$\lvert 00\rangle \xrightarrow{H_1} \tfrac{1}{\sqrt2}(\lvert 00\rangle + \lvert 10\rangle)
\xrightarrow{\mathrm{CNOT}_{12}} \tfrac{1}{\sqrt2}(\lvert 00\rangle + \lvert 11\rangle)$$

Its correlation structure, used in both teleportation and key distribution:

$$\langle \sigma_Z \otimes \sigma_Z\rangle = +1,\qquad
\langle \sigma_X \otimes \sigma_X\rangle = +1,\qquad
\langle \sigma_Y \otimes \sigma_Y\rangle = -1$$

> **The $Y$-basis sign is negative.** $\lvert\Phi^+\rangle$ *anti*-correlates under
> $\sigma_Y \otimes \sigma_Y$. Any protocol that harvests correlated bits from $Y$-basis
> measurements on this state must invert one party's outcome. Omitting the inversion
> produces a 100% error rate on $Y$-sifted positions.

---

## 4. Quantum Teleportation

Three qubits participate: $q_0$ carries $\lvert\psi_i\rangle$ (signer), $q_1$ and $q_2$
hold $\lvert\Phi^+\rangle$ (signer and verifier respectively).

Write $\lvert\psi\rangle = \alpha\lvert 0\rangle + \beta\lvert 1\rangle$. The joint state is

$$\lvert\psi\rangle_0 \otimes \lvert\Phi^+\rangle_{12}
= \tfrac{1}{\sqrt2}\left(\alpha\lvert 0\rangle(\lvert 00\rangle + \lvert 11\rangle)
+ \beta\lvert 1\rangle(\lvert 00\rangle + \lvert 11\rangle)\right)$$

The signer performs a Bell-state measurement on $(q_0, q_1)$, implemented as
$\mathrm{CNOT}_{0\to1}$ then $H_0$, then measures both into classical bits $c_0, c_1$.
Expanding in the Bell basis of $(q_0,q_1)$:

$$\lvert\psi\rangle_0\lvert\Phi^+\rangle_{12} = \tfrac{1}{2}\Big[
\lvert\Phi^+\rangle_{01}\lvert\psi\rangle_2
+ \lvert\Phi^-\rangle_{01}(\sigma_Z\lvert\psi\rangle_2)
+ \lvert\Psi^+\rangle_{01}(\sigma_X\lvert\psi\rangle_2)
+ \lvert\Psi^-\rangle_{01}(\sigma_X\sigma_Z\lvert\psi\rangle_2)\Big]$$

Each of the four outcomes occurs with probability $\tfrac14$, **independent of
$\lvert\psi\rangle$**. The signer's measurement therefore reveals nothing about the
signature state, and the verifier's qubit is left in a known Pauli image of it.

### 4.1 Pauli Correction Operations

The verifier restores the state by applying the correction indexed by $(c_0, c_1)$:

$$\lvert\psi\rangle_2 = \sigma_Z^{c_0}\,\sigma_X^{c_1}\,\lvert\tilde\psi\rangle_2$$

| $c_0$ | $c_1$ | Verifier's state before | Correction |
|---|---|---|---|
| 0 | 0 | $\lvert\psi\rangle$ | $I$ |
| 0 | 1 | $\sigma_X\lvert\psi\rangle$ | $\sigma_X$ |
| 1 | 0 | $\sigma_Z\lvert\psi\rangle$ | $\sigma_Z$ |
| 1 | 1 | $\sigma_X\sigma_Z\lvert\psi\rangle$ | $\sigma_X\sigma_Z$ |

Since $\sigma_X^2 = \sigma_Z^2 = I$, the correction is exact and teleportation is
lossless. Because $c_0, c_1$ are uniform and independent of $\lvert\psi\rangle$, the
classical channel leaks nothing.

**Teleportation does not authenticate.** It faithfully transports whatever state it is
given, from whoever supplies it. Authentication comes only from $K$, which determines
*which* state a legitimate signer would have supplied.

---

## 5. Projective Measurement Rules

The verifier rotates $q_2$ into the computational basis and measures.

| $B_i$ | Rotation | Justification |
|---|---|---|
| $Z$ | $I$ | Already the computational basis |
| $X$ | $H$ | $H\sigma_X H^\dagger = \sigma_Z$ |
| $Y$ | $H S^\dagger$ | $HS^\dagger \sigma_Y (HS^\dagger)^\dagger = \sigma_Z$ |

The projectors onto the $\pm1$ eigenspaces of observable $\sigma_B$ are

$$\Pi_\pm^{(B)} = \tfrac{1}{2}\left(I \pm \sigma_B\right),
\qquad \Pi_+ + \Pi_- = I,\qquad \Pi_\pm^2 = \Pi_\pm$$

By the Born rule, the outcome probability is

$$\Pr[\lambda = \pm 1] = \langle\psi\rvert \Pi_\pm^{(B)} \lvert\psi\rangle$$

Outcome bit $m_i \in \{0,1\}$ maps to eigenvalue $\lambda_i^{\text{obs}} = 1 - 2m_i$.

**Determinism on a noiseless channel.** If the verifier measures in the same basis in
which the state was prepared, then $\lvert\psi_i\rangle$ is an eigenstate of $\sigma_{B_i}$
and

$$\langle\psi_i\rvert \Pi_{\lambda_i}^{(B_i)}\lvert\psi_i\rangle = 1$$

The expected eigenvalue is obtained with certainty. This is what makes **deterministic
acceptance** of legitimate signatures possible: a noiseless channel yields exactly zero
verification errors, not merely few.

---

## 6. Verification Statistic and Decision Rule

Define the per-position error indicator and the aggregate error count:

$$E_i = \mathbb{1}\!\left[\lambda_i^{\text{obs}} \neq \lambda_i\right],
\qquad k = \sum_{i} E_i, \qquad \hat{e} = k/n$$

Under the null hypothesis of a legitimate signature on a calibrated channel,
$k \sim \mathrm{Binomial}(n, p_0)$.

### 6.1 Anomaly Test

$$H_0: p = p_0 \qquad\text{versus}\qquad H_1: p > p_0$$

with exact upper-tail $p$-value

$$\Pr[K \ge k \mid n, p_0] = \sum_{j=k}^{n}\binom{n}{j} p_0^{\,j}(1-p_0)^{\,n-j}$$

Reject $H_0$ when this falls below $\alpha$. The critical count is

$$k^* = \min\left\{k : \Pr[K \ge k \mid n, p_0] < \alpha\right\}$$

### 6.2 Three-Way Decision Rule

A single "accept iff $k = 0$" rule is correct only for $p_0 = 0$; on a noisy channel it
rejects every legitimate signature. Two thresholds are therefore used:

$$\sigma = \sqrt{\frac{p_0(1-p_0)}{n}},\qquad
s_a = p_0 + 3\sigma,\qquad
s_v = \frac{s_a + q_{\min}}{2}$$

where $q_{\min} = 1/3$ is the smallest error rate produced by any key-independent attack.

$$\text{verdict} = \begin{cases}
\textbf{ACCEPT} & \hat{e} \le s_a\\
\textbf{ABORT} & s_a < \hat{e} < s_v\\
\textbf{REJECT} & \hat{e} \ge s_v
\end{cases}$$

For $n = 256$, $p_0 = 0.02$: $\sigma = 0.00875$, $s_a = 0.0462$, $s_v = 0.1898$.

**Properties.**
1. A noiseless channel gives $\hat e = 0 \le s_a$: deterministic acceptance.
2. Calibrated noise stays below $s_a$ with probability $\approx 99.7\%$.
3. Every key-independent attack has $\hat e \ge 1/3 > s_v$: always REJECT.
4. Channel tampering is a continuum ($\hat e = \tfrac23 p$) and is **not** always
   rejected — see §7.1. No modelled attack is ever ACCEPTED except a bit-flip channel
   weaker than the calibrated noise floor, which is information-theoretically
   indistinguishable from that noise and forges nothing.

---

## 7. Attack Models and Their Analytic Signatures

### 7.1 Channel Tampering (Pauli-X Bit Flip)

The channel applies $\sigma_X$ with probability $p$:

$$\rho \mapsto (1-p)\,\rho + p\,\sigma_X \rho\, \sigma_X$$

Effect per basis:
- $Z$ basis: $\sigma_X\lvert 0\rangle = \lvert 1\rangle$ — eigenvalue flips, error.
- $Y$ basis: $\sigma_X\lvert {\pm i}\rangle = \mp i \lvert {\mp i}\rangle$ — error.
- $X$ basis: $\sigma_X\lvert \pm\rangle = \pm\lvert \pm\rangle$ — **invariant up to global
  phase, no error.**

With the uniform basis schedule, exactly $2/3$ of positions are sensitive:

$$\boxed{\;\hat e \to \tfrac{2}{3}p\;}\qquad
(e_Z, e_X, e_Y) \to (p,\; 0,\; p)$$

**X-basis immunity is the unique fingerprint of a bit-flip channel.** No other modelled
attack leaves an entire basis undisturbed.

### 7.2 Digest-Only Forgery

The adversary knows $M$ and $D$ but not $K$, and prepares states from $b_i' = d_i$
(equivalent to assuming $K = 0$). Since $b_i = d_i \oplus K_i$, the forged and expected
states are orthogonal in the same basis exactly where $K_i = 1$, giving a deterministic
error there and none elsewhere:

$$\hat e \to \rho_K \equiv \frac{1}{n}\sum_i K_i \qquad (=\tfrac12 \text{ for a balanced key})$$

The error indicator is a *copy of the key*, so the Matthews correlation between $E_i$ and
$K_i$ approaches $+1$ — the discriminator that separates forgery from impersonation.

### 7.3 Impersonation

The adversary guesses $b_i' \sim \mathrm{Bernoulli}(1/2)$ independently of $K$:

$$\hat e \to \tfrac12, \qquad \mathrm{MCC}(E, K) \to 0$$

Uniform across bases, uncorrelated with the key.

### 7.4 Intercept-Resend

The eavesdropper measures each intercepted qubit in a guessed basis $B_E$ and resends the
corresponding eigenstate. Her basis coincides with the signer's with probability $1/3$
(no disturbance); otherwise the state collapses into an orthogonal basis and the verifier's
outcome is uniform:

$$\hat e \to \tfrac13\cdot 0 + \tfrac23\cdot\tfrac12 = \boxed{\tfrac13}$$

Uniform across all three bases, and uncorrelated with $K$. This is the measurement–
disturbance trade-off that makes eavesdropping detectable, and it is a direct consequence
of the no-cloning theorem: the eavesdropper cannot copy the state and defer her basis
choice.

### 7.5 Replay

Let $D, D'$ be the bound digests of the captured and expected payloads. Since
$b_i = d_i \oplus K_i$ and $b_i' = d_i' \oplus K_i$, the key cancels and mismatches occur
exactly where the digests differ:

$$\hat e = \frac{d_H(D, D')}{n}$$

- **Different message, no freshness:** SHA-256's avalanche property gives
  $d_H/n \approx 1/2$. Detected.
- **Same message, no freshness:** $D = D'$, so $\hat e = 0$. **Undetectable by
  measurement** — there is nothing to measure. This is why §1 binds a nonce.
- **Same message, with freshness:** the verifier's nonce registry rejects the reused
  $\nu$ in $O(1)$, before any state is measured. If the adversary substitutes a fresh
  $\nu'$ to evade the registry, then $D \ne D'$ and she must re-derive all $n$ states for
  $D'$ without $K$ — which is exactly §7.2, detected at $\approx 50\%$ error.

### 7.6 Unauthorized Verification

A verifier proves entitlement with an HMAC-SHA256 token
$\tau = \mathrm{HMAC}_{K_M}(\mathrm{id})$, compared in constant time. Detection is
deterministic, with no false-positive rate. This is a **classical** mechanism; it is
included because the quantum layer cannot express *who* may measure a signature, and
because measurement destroys the signature, making unrestricted verification a
denial-of-service vector.

### 7.7 Signature Summary

| Attack | $e_Z$ | $e_X$ | $e_Y$ | $\mathrm{MCC}(E,K)$ | Discriminator |
|---|---|---|---|---|---|
| None | $p_0$ | $p_0$ | $p_0$ | $\approx 0$ | all at baseline |
| Channel tampering | $p$ | $\approx 0$ | $p$ | $\approx 0$ | **X-basis immunity** |
| Intercept-resend | $1/3$ | $1/3$ | $1/3$ | $\approx 0$ | uniform at $1/3$ |
| Forgery | $\rho_K$ | $\rho_K$ | $\rho_K$ | $\approx +1$ | **errors track $K_i=1$** |
| Impersonation | $1/2$ | $1/2$ | $1/2$ | $\approx 0$ | uniform at $1/2$ |
| Replay (diff. msg) | $d_H/n$ | $d_H/n$ | $d_H/n$ | $\approx 0$ | classical digest mismatch |
| Replay (same msg) | $p_0$ | $p_0$ | $p_0$ | $\approx 0$ | **nonce registry** |
| Unauthorized verify | — | — | — | — | **HMAC validation** |

**Resolution limit.** Two hypotheses predicting rates $q_a, q_b$ are separable only when

$$n \ge \frac{9\left(q_a(1-q_a) + q_b(1-q_b)\right)}{(q_a - q_b)^2}$$

at $3\sigma$. The tightest pair is intercept-resend ($1/3$) against impersonation
($1/2$), requiring $n \ge 153$. This is why classification is reliable at $n = 256$ and
unreliable on small subsets.

---

## 8. Forgery Probability Bound

An adversary without $K$ matches each position with probability $1/2$ (§1). A signature is
accepted when at most $t = \lfloor s_a n\rfloor$ positions disagree, so

$$\boxed{\;P_{\text{forge}}(n, s_a) = \sum_{j=0}^{\lfloor s_a n\rfloor}\binom{n}{j}\left(\tfrac12\right)^{n}\;}$$

with security level $-\log_2 P_{\text{forge}}$ bits.

| $n$ | $t$ | $P_{\text{forge}}$ | Security |
|---|---|---|---|
| 16 | 0 | $1.53\times10^{-5}$ | 16.0 bits |
| 64 | 2 | $1.13\times10^{-16}$ | 53.0 bits |
| 256 | 11 | $5.64\times10^{-59}$ | 193.5 bits |

The bound decays exponentially in $n$ and holds against an adversary with **unbounded
computational power**, including a quantum computer: the adversary lacks *information*
about $K$, not merely the time to compute it. Shor's algorithm has nothing to attack.

**Caveat.** The $1/2$ per-position rate assumes $K$ is uniformly random. For a forger who
assumes $K = 0$, the per-position success rate is $1 - \rho_K$, so a biased or publicly
guessable key destroys the bound. A degenerate all-zero key gives $P_{\text{forge}} = 1$.
Keys must come from §10 or a CSPRNG.

---

## 9. Detection Power

Against a true attack rate $q$, the detector's power and size are

$$\text{Power} = \Pr[K \ge k^* \mid n, q],\qquad
\text{Size} = \Pr[K \ge k^* \mid n, p_0]$$

For $n = 256$, $p_0 = 0.02$, $\alpha = 0.05$ ($k^* = 10$):

| Attack | $q$ | Power | False-positive rate |
|---|---|---|---|
| Channel tampering, $p=0.10$ | 0.0667 | 0.978 | 0.0348 |
| Channel tampering, $p=0.50$ | 0.3333 | $>0.999999$ | 0.0348 |
| Intercept-resend | 0.3333 | $>0.999999$ | 0.0348 |
| Forgery / Impersonation / Replay | 0.5 | $>0.999999$ | 0.0348 |

---

## 10. Quantum Key Establishment (BBM92)

Rather than assuming a pre-shared $K$, it is established by entanglement-based key
distribution. For each raw bit a $\lvert\Phi^+\rangle$ pair is split; both parties measure
in independently chosen random bases; mismatched positions are discarded (sifting).

Using the correlations of §3, matched-basis outcomes agree in $Z$ and $X$ and
**anti**-agree in $Y$, where one party inverts.

An intercept-resend eavesdropper on $B$ bases guesses correctly with probability $1/B$,
giving a sifted-bit error rate

$$\mathrm{QBER} = \left(1 - \tfrac{1}{B}\right)\cdot\tfrac12
\qquad\Rightarrow\qquad
B=2:\;25\%,\quad B=3:\;33.3\%$$

An honest channel on an ideal simulator yields $\mathrm{QBER} = 0$. The QBER is estimated
from a disclosed random sample (then discarded) and tested with the same exact binomial
detector of §6.1.

**Scope.** Basis reconciliation is assumed to occur over an authenticated public channel.
No information reconciliation or privacy amplification is implemented, so the sifted key
is **not** composably secure; this models the distribution and eavesdropper-detection
stages only.

---

## 11. Computational Complexity

| Stage | Complexity | Note |
|---|---|---|
| SHA-256 digest | $O(\lvert M\rvert)$ | Independent of $n$ |
| Session binding | $O(1)$ | Concatenation and one hash |
| Encoding ($\oplus$, basis map) | $O(n)$ | Single pass |
| Verifier authorization | $O(1)$ | One HMAC, constant-time compare |
| Nonce freshness check | $O(1)$ | Hash-set membership |
| Teleportation + measurement | $O(n)$ | $n$ independent 3-qubit circuits |
| Binomial detector | $O(n)$ | One exact tail evaluation |
| Threat classification | $O(n)$ | One pass for the basis profile |
| **Total** | $\mathbf{O(n)}$ | No stage exceeds $O(n)$ |

Measured empirically (ideal simulator, $n \in \{16,\dots,256\}$, minimum of 3 timed runs
after warm-up): log-log slope $= 1.01$, $R^2 = 0.9997$, confirming linear scaling at
$\approx 1.7$ ms per position. The constant factor is dominated by simulator overhead, not
protocol arithmetic.

---

## 12. Security Scope and Disclosures

**Provided.**
- Information-theoretic unforgeability against key-independent adversaries, with
  $P_{\text{forge}}$ decaying exponentially in $n$ (§8).
- Eavesdropping detection via the measurement–disturbance trade-off (§7.4).
- Deterministic acceptance of legitimate signatures on a noiseless channel (§5).
- Replay resistance through nonce binding (§7.5).
- Threat classification from analytic per-basis signatures (§7.7).

**Not provided.**
- **Non-repudiation / transferability.** A true QDS scheme lets a recipient forward a
  signature to a third party who reaches the same verdict. This implementation is a
  two-party authentication scheme; $K$ is shared, so the verifier could have produced any
  signature the signer could. Transferability requires per-recipient key halves and a
  two-threshold construction (Gottesman–Chuang).
- **Composable key security.** No privacy amplification (§10).
- **Coherent / collective attacks.** Only individual-qubit adversaries are modelled.
- **Authenticated classical channel.** Assumed, not implemented.
- **Side-channel resistance.** Out of scope, except for constant-time token comparison.

**Methodological disclosures.**
- $p_0$ is a calibrated experimental parameter, not a universal constant.
- Statistical detection establishes inconsistency with calibrated noise; it does not prove
  adversarial intent.
- Classification uses deterministic distance scoring against closed-form signatures. No
  artificial intelligence or machine learning is used anywhere in the framework.
- All reported error rates arise from executed Qiskit circuits; none are hardcoded.

---

## References

1. C. H. Bennett and G. Brassard, "Quantum cryptography: Public key distribution and coin
   tossing," *Proc. IEEE Int. Conf. Computers, Systems and Signal Processing*, 1984.
2. C. H. Bennett, G. Brassard, C. Crépeau, R. Jozsa, A. Peres, W. K. Wootters,
   "Teleporting an unknown quantum state via dual classical and Einstein-Podolsky-Rosen
   channels," *Phys. Rev. Lett.* **70**, 1895 (1993).
3. C. H. Bennett, G. Brassard, N. D. Mermin, "Quantum cryptography without Bell's theorem,"
   *Phys. Rev. Lett.* **68**, 557 (1992). — BBM92
4. D. Gottesman and I. Chuang, "Quantum Digital Signatures," arXiv:quant-ph/0105032 (2001).
5. W. K. Wootters and W. H. Zurek, "A single quantum cannot be cloned," *Nature* **299**,
   802 (1982).
6. M. A. Nielsen and I. L. Chuang, *Quantum Computation and Quantum Information*,
   Cambridge University Press, 10th Anniversary Ed., 2010.
