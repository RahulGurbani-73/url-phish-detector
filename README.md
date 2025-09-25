# URL Phishing Detector 🔍🛡️

A **rule-based URL phishing detector** with a modern cyber-neon dashboard UI.
It detects suspicious URLs and classifies them as **Likely Safe**, **Suspicious**, or **Likely Phishing** using heuristics such as suspicious keywords, host anomalies, TLD checks, WHOIS domain age, and blacklist matching.

This project is intended **for educational purposes only**.

---

## Features 🚀

* **Rule-based URL scoring** with clear reasons for suspicion
* **Suspicious keywords** in path and host detection
* **Blacklist domain detection**
* **IP address & @ symbol check**
* **Long URL, hyphen, subdomain, TLD, non-standard port checks**
* **WHOIS domain age check** (penalizes very new domains)
* **Animated radar scanner and cyber-neon UI**
* **Threat meter** with glowing progress bar
* **QR code generation** for safe URLs
* **Bulk CSV scanning** and export
* **Clipboard copy/share of results**
* **Flask web app** with modern dashboard feel

---

## Repo Structure

```
url-phish-detector/
├── README.txt
├── requirements.txt
├── app.py
├── phish_detector.py
├── templates/
│   └── index.html
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── main.js
```

---

## Quick Start 🏁

### 1. Clone the repository

```
git clone https://github.com/<your-username>/url-phish-detector.git
cd url-phish-detector
```

### 2. Create a virtual environment

**Windows (CMD/PowerShell):**

```
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS:**

```
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```
pip install -r requirements.txt
```

### 4. Run the app

```
python app.py
```

### 5. Open in browser

Go to [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Usage 🖥️

1. **Enter URL** in the input box
2. **Click Scan**
3. **View result**:

   * Label: `Likely Safe` / `Suspicious` / `Likely Phishing`
   * Threat score
   * Reasons for suspicion
   * Optional QR code for safe URLs
4. **Bulk scan CSV** (upload multiple URLs at once)
5. **Export results** as CSV
6. **Share / Copy link** of results

---

## Example Test URLs

| URL                                                                              | Expected Result |
| -------------------------------------------------------------------------------- | --------------- |
| [http://192.168.0.1/login](http://192.168.0.1/login)                             | Likely Phishing |
| [http://paypal-secure-login.example.com](http://paypal-secure-login.example.com) | Suspicious      |
| [https://www.google.com](https://www.google.com)                                 | Likely Safe     |
| [http://example.com@evil.com/login](http://example.com@evil.com/login)           | Likely Phishing |

---

## Safety & Ethics ⚠️

* **Do not** scan domains without permission.
* **Do not** deploy to interfere with third-party websites.
* Intended **for educational & personal learning purposes only**.

---

## Dependencies 📦

* Python 3.8+
* Flask
* tldextract
* validators
* python-whois
* qrcode

Install all dependencies with:

```
pip install -r requirements.txt
```

---

## License 📝

MIT License
Feel free to modify and share this project for educational purposes.
