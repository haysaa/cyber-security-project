
# Zero-Day Attack Detection via Deep Anomaly Analysis

**An Autoencoder-Based Intrusion Detection System for Unknown Network Threats**

> Final project Cyber Security and Ethics
> Authors: Hayrunnisa Açıkgöz (23LYAZ032) · Burak Can Tarhan (23LBIM022)
> Istanbul Ticaret University

---

## 1. Overview

Traditional Intrusion Detection Systems (IDS) rely on signature databases to identify malicious traffic. They are effective against known attacks but fundamentally blind to zero-day exploits attacks that target previously undisclosed vulnerabilities and therefore have no signature yet. A signature-based IDS will let a zero-day exploit pass undetected until vendors release a patch and analysts publish a new rule.

This project proposes an alternative: a behavior-based, anomaly-driven detector that does not need to have seen an attack before. We train a Deep Autoencoder on legitimate network traffic only. The model learns what "normal" looks like. At inference time, any traffic flow that the model cannot reproduce accurately is flagged as suspicious regardless of whether it matches any known attack signature.

The system is evaluated on two real-world network intrusion datasets (UNSW-NB15 v2 and CSE-CIC-IDS2018) covering 23 distinct attack families ranging from DDoS and brute-force to SQL injection, XSS, and infiltration.

---

## 2. The Zero-Day Threat

Zero-day attacks are responsible for some of the highest-impact security incidents in recent years (SolarWinds, Log4Shell, Microsoft Exchange ProxyLogon). They share three characteristics that make signature-based detection impossible:

1. The vulnerability is unknown to the vendor and the security community.
2. No public IDS rule, antivirus signature, or YARA pattern exists.
3. The attack may already be in active use by adversaries before any defensive measure can be deployed.

Defenders need detection mechanisms that do not depend on prior knowledge of the attack. This project investigates one such mechanism: unsupervised deep learning on network traffic features.

---

## 3. Methodology

### 3.1 Hypothesis

A neural network trained exclusively on benign network traffic will fail to reconstruct anomalous traffic accurately. The magnitude of this reconstruction failure measured as Mean Squared Error (MSE) can be used as an anomaly score.

### 3.2 Vanilla Deep Autoencoder (AE)

```
Encoder:  d → 128 → 64 → 32 → 8     (ReLU + BatchNorm)
Decoder:  8 → 32 → 64 → 128 → d     (ReLU + BatchNorm, Sigmoid output)
```

The model compresses each network flow record into an 8-dimensional latent representation, then reconstructs it. Training minimizes the reconstruction loss on benign traffic only:

```
L(x) = ‖x − decoder(encoder(x))‖²
```

At inference, each new flow is scored by its reconstruction error. Flows with errors above a calibrated threshold are flagged as malicious.

### 3.3 Denoising Autoencoder (DAE)

Same architecture, hardened training procedure. Each input is corrupted with small Gaussian noise during training, and the model must recover the clean original:

```
x̃ = clamp(x + ε, 0, 1),   ε ~ 𝒩(0, σ²),   σ = 0.05
L(x) = ‖x − decoder(encoder(x̃))‖²
```

This forces the encoder to learn noise-invariant features and, as we will show, improves detection of low-volume and stealthy attack categories.

### 3.4 Detection Threshold

Two strategies were evaluated:

- **95th percentile** of normal reconstruction errors high precision, low recall (misses many attacks).
- **Youden Index** maximizes True Positive Rate minus False Positive Rate; chosen as the primary operating point for its balanced trade-off.

### 3.5 Baselines

To verify that the deep approach is justified, we compare against two classical anomaly detectors:

- **Isolation Forest** tree-based isolation of outliers; widely used in security analytics.
- **One-Class SVM** support vector method for one-class classification.

Both baselines are trained on the exact same benign-only training set.

---

## 4. Datasets

| | UNSW-NB15 v2 | CSE-CIC-IDS2018 |
|---|---|---|
| Source | UNSW Canberra Cyber, ACCS | Canadian Institute for Cybersecurity |
| Total flow records | 1,986,745 | ~2.5M (after sampling) |
| Attack ratio | 3.78% | ~77% |
| Attack families | 9 (Exploits, Reconnaissance, DoS, Backdoor, Shellcode, Fuzzers, Generic, Analysis, Worms) | 14 (DDoS-HOIC, DDoS-LOIC-HTTP, DoS-Hulk, Bot, FTP-Brute, SSH-Brute, Infiltration, Brute Force-Web, Brute Force-XSS, SQL Injection, etc.) |
| Raw features | 43 NetFlow v2 | 80 (CICFlowMeter) |

Each dataset captures realistic enterprise traffic combined with controlled attack campaigns. Together they cover both well-known volumetric attacks (DDoS, port scanning) and stealthy application-layer attacks (XSS, SQL Injection, infiltration).

### 4.1 Preprocessing

To prevent label leakage all preprocessing statistics are computed exclusively on the benign training subset:

1. Drop identifier and timestamp columns (IP addresses, ports as identifiers, timestamps)
2. Replace inf/NaN values with the median from benign training data
3. Remove low-variance features (var ≤ 0.01)
4. Remove highly correlated features (|r| > 0.95)
5. MinMaxScaler fit on benign training data only, then applied to all splits

Final feature counts: UNSW-NB15 v2 → 31, CSE-CIC-IDS2018 → 41.

---

## 5. Training

- Framework: PyTorch
- Optimizer: Adam (lr=1e-3)
- Batch size: 1024
- Epochs: 50
- LR scheduler: ReduceLROnPlateau (factor=0.5, patience=5)
- Hardware: NVIDIA T4 GPU (Kaggle)

The model never sees an attack during training. This is the central property of the approach: we do not depend on having previously captured attack samples, which is precisely the condition under which signature-based systems fail.

---

## 6. Results

### 6.1 Detection Performance

| Model | Dataset | ROC-AUC | PR-AUC | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| **Vanilla AE** | UNSW-NB15 v2 | **0.9874** | 0.7490 | 0.466 | 0.963 | 0.628 |
| DAE | UNSW-NB15 v2 | 0.9714 | 0.6155 | 0.238 | 0.958 | 0.381 |
| Isolation Forest | UNSW-NB15 v2 | 0.8510 | 0.1118 | | | |
| One-Class SVM | UNSW-NB15 v2 | 0.7380 | 0.2020 | | | |
| Vanilla AE | CSE-CIC-IDS2018 | 0.8126 | 0.9314 | 0.894 | 0.962 | 0.927 |
| **DAE** | CSE-CIC-IDS2018 | **0.8757** | **0.9542** | 0.918 | 0.944 | 0.931 |

All scores use the Youden threshold. The autoencoder approach outperforms Isolation Forest by **+0.14 ROC-AUC** and One-Class SVM by **+0.25 ROC-AUC** on UNSW-NB15 v2.

### 6.2 Attack-Family Detection

**UNSW-NB15 v2** (Vanilla AE, Youden threshold):

| Attack Family | Recall |
|---|---|
| Generic | 0.987 |
| Reconnaissance | 0.977 |
| Backdoor | 0.974 |
| Fuzzers | 0.967 |
| Exploits | 0.954 |
| DoS | 0.950 |
| Shellcode | 0.993 |
| Worms | 0.969 |
| Analysis | 0.832 |

**CSE-CIC-IDS2018** (DAE, Youden threshold) selected results:

| Attack Family | Vanilla AE | DAE |
|---|---|---|
| Brute Force-XSS | 0.694 | **0.980** |
| SQL Injection | 0.750 | **0.812** |
| Brute Force-Web | 0.796 | **0.839** |
| DDoS-HOIC | 1.000 | 1.000 |
| DoS-Hulk | 1.000 | 0.999 |
| SSH-Bruteforce | 1.000 | 1.000 |

The DAE provides substantial gains on the most security-critical categories: web-layer injection attacks (XSS, SQL Injection) and brute-force attempts that conventional rule-based systems often miss due to their low volume and resemblance to legitimate traffic.

### 6.3 Threshold Sensitivity

On CSE-CIC-IDS2018, the 95th percentile threshold yields a recall of only 0.39 unacceptable for a production IDS. The Youden Index raises recall to 0.96 with only a modest precision drop. This demonstrates that proper threshold calibration is not optional in security deployments; it is the difference between catching attacks and missing them.

---

## 7. Security Findings

1. **Behavior-based detection works against zero-day threats.** A model that has never seen an attack still detects 96%+ of malicious traffic by reconstruction error alone.
2. **Deep learning outperforms classical anomaly detectors.** Isolation Forest and One-Class SVM, while commonly used in security analytics, are significantly outperformed by both AE variants.
3. **Stealthy application-layer attacks benefit from denoising regularization.** XSS recall jumps from 0.69 to 0.98 with DAE precisely the category that signature-based WAF systems struggle with.
4. **Cross-environment transfer fails.** A model trained on one network environment cannot be directly deployed to another (ROC-AUC drops to 0.24 on cross-dataset evaluation). Each deployment requires domain-specific training a meaningful operational constraint.
5. **No single model wins everywhere.** Defenders should benchmark both AE and DAE on their own traffic and select per environment.

---

## 8. Limitations & Operational Considerations

- **Feature engineering dependency.** The model operates on aggregated NetFlow / CICFlowMeter features, not raw packets. Adversaries who can manipulate flow-level statistics may evade detection.
- **No real-time latency benchmarks.** Inference speed must be validated against production traffic rates before deployment.
- **Concept drift.** Normal traffic patterns change over time (new applications, new user behavior). The model needs periodic retraining or online adaptation.
- **Adversarial robustness.** An attacker with knowledge of the model could craft traffic that reconstructs well (low error). Defenses against adversarial evasion are out of scope.
- **Class imbalance.** Some categories (Infiltration, Analysis) remain hard with recalls around 0.40-0.55. Hybrid approaches (autoencoder + supervised classifier on flagged samples) could help.

---

## 9. Project Structure

```
project/
├── README.md
├── notebooks/
│   ├── unsw_pipeline.ipynb       # Preprocessing + training + evaluation
│   └── cse_pipeline.ipynb
├── model/
│   ├── unsw_ae_weights.pt        # Trained autoencoder weights
│   ├── scaler_unsw.pkl           # Fitted MinMaxScaler
│   └── keep_cols_unsw.pkl        # Selected feature names
├── demo/
│   ├── backend.py                # FastAPI inference server
│   └── index.html                # Web demo UI
├── figures/
│   ├── roc_comparison_unsw.png
│   ├── roc_comparison_cse.png
│   ├── category_comparison_unsw.png
│   ├── category_comparison_cse.png
│   ├── error_distribution_unsw.png
│   ├── error_distribution_cse.png
│   ├── training_curve_unsw.png
│   └── training_curve_cse.png
└── requirements.txt
```

---

## 10. How to Reproduce

### 10.1 Train the Detector

Open `notebooks/unsw_pipeline.ipynb` on Kaggle (or any environment with GPU access) and run all cells. The pipeline handles:

- Loading raw NetFlow records
- Filtering identifiers and applying privacy-aware preprocessing
- Training the autoencoder on benign traffic only
- Evaluating against held-out attack samples
- Computing per-attack-family detection rates
- Saving the trained model and preprocessing artifacts

Repeat with `notebooks/cse_pipeline.ipynb` for the second dataset.

### 10.2 Run the Live Demo

```bash
cd demo/
pip install -r ../requirements.txt
python backend.py
```

Open `http://localhost:8000` in a browser. Paste a network flow record (31 comma-separated NetFlow v2 features) or click one of the preset example buttons (Normal Traffic, Exploit Attack, Reconnaissance). The system returns:

- A binary verdict: **SAFE** or **MALICIOUS**
- A confidence score
- The exact reconstruction error and the configured threshold

The demo runs entirely on the local machine; no traffic leaves the host.

### 10.3 Dependencies

```
torch
scikit-learn
pandas
numpy
joblib
fastapi
uvicorn
matplotlib
```

---

## 11. References

- Moustafa, N., & Slay, J. (2015). *UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems*. MilCIS.
- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.
- Bilge, L., & Dumitras, T. (2012). *Before We Knew It: An Empirical Study of Zero-Day Attacks in the Real World*. ACM CCS.
- An, J., & Cho, S. (2015). *Variational Autoencoder based Anomaly Detection using Reconstruction Probability*. SNU Data Mining Center.
- Vincent, P., et al. (2008). *Extracting and Composing Robust Features with Denoising Autoencoders*. ICML.
- Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. ICDM.
- Schölkopf, B., et al. (2001). *Estimating the Support of a High-Dimensional Distribution*. Neural Computation.
- Youden, W. J. (1950). *Index for Rating Diagnostic Tests*. Cancer.
- Mirsky, Y., et al. (2018). *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*. NDSS.

---

## 12. Ethical Considerations

This work is purely defensive in nature. The datasets used are public research benchmarks containing synthetic and controlled attack traffic. No real attack tools, exploits, or vulnerability details are produced by this project. The detector is designed to protect networks, not to facilitate offensive operations.

---

## 13. License

This project is submitted as coursework for academic purposes.
