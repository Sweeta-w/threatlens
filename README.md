# 🛡️ ThreatLens — IP, Domain & URL Safety Analyzer

ThreatLens is a lightweight **Streamlit** web app that checks whether an **IP address, domain, or URL** looks safe or suspicious. It pulls evidence from **VirusTotal** and **WHOIS**, then uses an **LLM (Groq — Llama 3.3 70B)** to turn that raw evidence into a plain-language, color-coded verdict tailored to your knowledge level (Beginner / Intermediate / Expert).

> ⚠️ This is an educational security-awareness tool, not a replacement for a professional security investigation.

---

## 🔗 Live Demo

**[Try ThreatLens live →](YOUR_LIVE_APP_LINK_HERE)**

---

## ✨ Features

- 🔍 Analyze **IP addresses**, **domains**, and **URLs** in one interface
- 🧠 AI-generated verdict — `SAFE`, `SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN` — with confidence level
- 🎓 Explanation style adapts to your knowledge level (Beginner / Intermediate / Expert)
- 🟢🟠🔴⚪ Color-coded verdict card for instant readability
- 📋 Transparent, expandable raw source results (VirusTotal + WHOIS)
- 🧩 **Plug-and-play architecture** — new intelligence sources (e.g. AbuseIPDB) can be added with just one function + one registry entry, no UI/orchestration changes needed
- 🛡️ Graceful error handling — if one source fails, the rest of the app still works
- 🔐 No hardcoded secrets — API keys are read from environment variables / Streamlit secrets only

---

## 🏗️ Architecture

```text
threatlens/
├── app.py            # Streamlit UI, orchestration, LLM prompt + call, result rendering
├── sources.py         # Intelligence sources (VirusTotal, WHOIS) + SOURCES registry
└── requirements.txt   # Python dependencies
```

**One-way dependency:** `app.py → sources.py` (never the reverse). `sources.py` has zero Streamlit or LLM logic — it only fetches and normalizes data.

### Adding a new intelligence source

```python
# In sources.py
def get_abuseipdb(target_type, target):
    ...
    return {"source": "AbuseIPDB", "status": "success", "data": {...}, "error": None}

SOURCES["AbuseIPDB"] = get_abuseipdb
```

That's it — `app.py` automatically calls it, includes its data in the LLM prompt, and renders it in the Source Results section. No other code changes required.

---

## 🛠️ Tech Stack

| Layer | Tool |
|---|---|
| UI / App framework | [Streamlit](https://streamlit.io) |
| Threat intelligence | [VirusTotal API](https://www.virustotal.com/) |
| Domain registration data | [WHOIS](https://pypi.org/project/python-whois/) |
| AI analysis | [Groq API](https://groq.com/) (Llama 3.3 70B) |
| Language | Python 3.10+ |

---

## 🚀 Getting Started (Local)

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/threatlens.git
cd threatlens
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Set your API keys

Create a `.streamlit/secrets.toml` file:

```toml
VT_API_KEY = "your_virustotal_api_key"
GROQ_API_KEY = "your_groq_api_key"
```

Or set them as environment variables:

```bash
export VT_API_KEY="your_virustotal_api_key"
export GROQ_API_KEY="your_groq_api_key"
```

### 4. Run the app

```bash
streamlit run app.py
```

---

## 🔑 Getting API Keys (free)

| Key | Where to get it |
|---|---|
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com/) → create account → Profile → API Key |
| `GROQ_API_KEY` | [console.groq.com](https://console.groq.com/keys) → create free API key |

---

## ☁️ Deployment

This app is deployed on **[Streamlit Community Cloud](https://share.streamlit.io)**:

1. Push this repo to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io) → **Create app**
3. Select this repo, branch `main`, main file `app.py`
4. Add `VT_API_KEY` and `GROQ_API_KEY` under **App settings → Secrets**
5. Deploy 🚀

---

## 📋 How It Works

```text
Select target type (IP / Domain / URL)
        ↓
Enter target + select knowledge level
        ↓
Validate input
        ↓
Collect results from every source in SOURCES (VirusTotal, WHOIS, ...)
        ↓
Build a knowledge-level-aware prompt from the collected evidence
        ↓
Groq LLM analyzes the evidence (never invents findings)
        ↓
Display: color-coded verdict → AI insight → raw source results
```

---

## ⚠️ Disclaimer

ThreatLens is built for **learning and general security awareness**. Verdicts are generated from third-party API data and an LLM's interpretation of that data — they are **not a guarantee of safety or maliciousness**. Always use professional security tools and judgment for real investigations.

---

## 👤 Author

Built by **[Sweeta]([https://www.linkedin.com/in/sweeta-k-7103972a6/])**

- 🔗 LinkedIn: ((https://www.linkedin.com/in/sweeta-k-7103972a6/))
- 🌐 Live App: [https://threatlens-by-sweeta.streamlit.app/]

---

## 📄 License

This project is open-sourced for educational purposes. Feel free to fork and extend it.
