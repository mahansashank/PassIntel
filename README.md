# PassIntel: Password Security Suite

An interactive, client-side cybersecurity tool designed to analyze password strength and generate cryptographically secure passwords. 

**Developed by**: P. Mahan Sashank Yadav  
**Affiliation**: Cybersecurity Student, Chandigarh University  
**Project Scope**: Pinnacle Labs CS Internship Submission

---

## 🚀 Live Demo & Visuals

The application is built as a responsive cybersecurity dashboard. It divides the workspace into a dual-column layout:
1. **Password Strength Analyzer**: Analyzes length, character pools, common dictionary leaks, repeats, keyboard sequences, and outputs an overall strength score (0–100) and Shannon Entropy value.
2. **Secure Password Generator**: Generates high-entropy passwords using the web browser's cryptographically secure pseudo-random number generator (CSPRNG) API with customizable length and character sets.

---

## 🛠️ Key Features

- **Real-Time Analysis**: Evaluates password strength dynamically as the user types.
- **Shannon Entropy Measurement**: Computes entropy in bits ($H = L \log_2(R)$) to estimate guess-randomness.
- **Dictionary Leak Check**: Cross-references passwords against a cleaned database of common dictionary terms.
- **Complexity Checklist**: Audits criteria like uppercase/lowercase mix, numbers, special symbols, runs/sequences (e.g., `abc`, `123`), and identical character repetitions.
- **Brute-Force Estimate**: Calculates estimated time-to-crack using a baseline GPU computing benchmark ($1 \times 10^{10}$ guesses/sec).
- **Secure Generation (CSPRNG)**: Selects random characters using `window.crypto.getRandomValues()` instead of insecure pseudo-random libraries.
- **Local Sandbox Execution**: No backend connections or APIs; all operations run locally in the client browser to preserve user privacy.

---

## 📁 Repository Structure

The project has been organized into a professional, modular web structure:

```text
Password analyzer/
├── index.html       # Semantically structured interface containing layout sections
├── style.css        # Custom CSS styling, color variables, and responsive grid layouts
├── app.js           # Core analysis algorithms, CSPRNG generator, and event handling
└── README.md        # Technical project documentation and guidelines
```

---

## 🧮 Cybersecurity Principles Applied

### 1. Shannon Entropy Formula
To evaluate password randomness, the suite calculates entropy ($H$) in bits:
$$H = L \times \log_2(R)$$
Where:
- $L$ = Length of the password.
- $R$ = Size of the character pool (charset).
  - Lowercase only: $R = 26$
  - Uppercase + Lowercase: $R = 52$
  - Alphanumeric (Upper, Lower, Numbers): $R = 62$
  - Full Set (Upper, Lower, Numbers, Symbols): $R = 94$

### 2. Guess Work Effort & Crack Time
Brute-force crack time estimates assume an attacker runs a high-performance offline crack rig achieving **10 billion guesses/second** ($1 \times 10^{10}$ attempts/sec). The formula to calculate time ($T$) is:
$$T = \frac{R^L}{2 \times 10^{10}} \text{ seconds}$$
*(Divided by 2 as success is typically achieved halfway through the search space).*

---

## 📜 Version History

*   **v1.0 (Initial Prototype)**
    *   Single-file `index.html` deployment.
    *   Basic client-side analysis and checklist audits.
    *   Standard inline script patterns.
*   **v1.1 (Modular Rewrite & Suite Upgrade) - Current Version**
    *   Refactored code structure into independent modules (`index.html`, `style.css`, `app.js`).
    *   Rebranded project from PassGuard to **PassIntel**.
    *   Added the **Secure Password Generator** leveraging Web Cryptography CSPRNG APIs.
    *   Cleaned and alphabetized dictionary checklist, removing AI duplicate list items.
    *   Built copy-to-clipboard functionality and clipboard sharing with the analyzer.
    *   Implemented user feedback toasts and polished the design to a responsive dual-column dashboard.

---

## 💡 Future Enhancements

As this application evolves, several advanced cybersecurity features are planned:
1.  **API Integration with Pwned Passwords**: Querying the *Have I Been Pwned* API using secure k-anonymity hashing protocols (SHA-1 prefixing) to cross-reference against over 800 million compromised passwords.
2.  **Visual Entropy Graphing**: Integrating a lightweight charting tool (like Chart.js) to graph entropy vs password length interactively.
3.  **Local History Log**: Persisting a session history log of password strengths in a local, encrypted IndexedDB sandbox for historical comparison.
4.  **Custom Dictionary Uploads**: Allowing cybersecurity administrators to load their own custom blacklists of domain-specific terms (like company names or team terms) for specialized audits.

---

## 🧑‍💻 How to Run Locally

Since PassIntel is built entirely on native web standards, it does not require an installation or build system.

1. Clone or download this directory.
2. Open the `index.html` file in any modern web browser (Chrome, Edge, Firefox, Safari).
3. Alternatively, run a local development server (e.g. VS Code Live Server extension) for quick hot-reloading.

---

## 📝 License & Ownership
Copyright © 2026 P. Mahan Sashank Yadav.  
Developed as an educational demonstration project for the Pinnacle Labs CS Internship. All calculations, styling, and structural elements are modularized and documented for readability and educational review.

---

## Developer Note

This project was developed as part of my cybersecurity learning journey and internship work. It helped me understand password security principles such as entropy, brute-force resistance, secure random generation, and common password vulnerabilities.