# 🎓 PhishGuard: Presentation & Viva Guide for Class Submission
**Student:** Vishal Pal ([vishalpal9868@gmail.com](mailto:vishalpal9868@gmail.com))  
**Program:** IBM SkillsBuild Cyber Security Bootcamp (October 2026) | Conducted by BharatCares  

This guide contains **exact scripts, talking points, and anticipated viva/exam questions** to help you present PhishGuard with confidence and score top marks.

---

## ⏱️ 1. The 30-Second Elevator Pitch (Start with this)

> *"Good morning/afternoon, Sir/Ma'am. My name is **Vishal Pal**. For my project in the **IBM SkillsBuild Cyber Security Bootcamp conducted by BharatCares**, instead of monitoring internal login logs, I built **PhishGuard** — an automated Threat Intelligence and Heuristic Phishing Detection Suite.*
>
> *Phishing is the number one attack vector in the world, responsible for over 80% of data breaches. My project allows an analyst to inspect suspicious URLs and emails in real-time. It uses **Shannon Entropy mathematical analysis**, **visual homoglyph detection**, **brand impersonation mapping**, and **social engineering NLP triggers** to generate a calibrated threat score from 0 to 100, along with an automated SOC incident report."*

---

## 🎯 2. When the Teacher Asks: "How is this different from my demo project?"

**Your exact answer:**
> *"Sir, your demo project (**CyberShield**) focused on **Internal Authentication Log Auditing** — counting how many times an IP failed to log in to detect a brute-force attack on a local database.*
>
> *I wanted to explore a completely different domain of cybersecurity: **External Threat Intelligence and Social Engineering Defense**.*
>
> *Here is the difference:*
> 1. *Your project processes historical login CSV records; **my project analyzes live URLs and raw email text**.*
> 2. *Your project uses a frequency threshold (`count >= 5`); **my project uses Shannon Entropy formulas, lexical tokenization, and DNS hierarchy parsing**.*
> 3. *My tool catches advanced attacks that traditional filters miss — like **homoglyph substitution** (`micros0ft.com`), **subdomain camouflage**, **risky TLDs**, and **CEO wire transfer fraud**.*
> 4. *I also added an interactive **Security Awareness Quiz** and an **Incident Report Exporter** for SOC teams."*

---

## 💻 3. Live Demo Step-by-Step Script (During Presentation)

### Step 1: Open the Application
Run in terminal:
```bash
streamlit run app.py
```

### Step 2: Demonstrate the URL Scanner (Tab 1)
1. Point out the sleek dark SOC dashboard interface.
2. Click the quick button: **`🚨 Test Homoglyph .xyz`**
   - Show how the URL looks visually like Microsoft (`https://security-update-micros0ft.support-verify.xyz/login.html`).
   - Click **Scan Target**.
   - **Show the result:**
     - Threat Score: **100 / 100 (Critical Threat)**
     - Show the specific flags triggered:
       - *Character Substitution Detected: '0' impersonating 'o' to mimic Microsoft.*
       - *High-Risk TLD: `.xyz`.*
       - *Brand Impersonation: Claims Microsoft on an unverified root domain.*
3. Now click: **`✅ Test Official PayPal`** (`https://www.paypal.com/signin`)
   - Click **Scan Target**.
   - Show the result: **0 / 100 (Safe / Legitimate)** with zero red flags!
   - Explain: *"This proves our heuristic engine doesn't produce false positives on real enterprise sites."*
4. Show the **"Download SOC Incident Report"** button to demonstrate real-world utility.

### Step 3: Demonstrate Email & Social Engineering Inspector (Tab 2)
1. Switch to **Tab 2: Email Phishing Inspector**.
2. Click: **`🚨 Fake PayPal Urgent Notice`**.
3. Click **Analyze Email Threat**.
4. Highlight how the engine catches:
   - **Sender Spoofing:** Display name says "PayPal Support", but sender email is `@paypa1-security-alert.xyz`.
   - **Urgency Manipulation:** Words like "within 24 hours", "suspended", "legal escalation".
   - **Automated URL Extraction:** The engine automatically extracted the embedded phishing link inside the email body and scanned it separately!

### Step 4: Show the Interactive Quiz (Tab 4)
1. Switch to **Tab 4: Security Quiz**.
2. Invite the teacher or class to answer Question 1 or 5.
3. Submit and show the immediate educational feedback and scoring.

---

## ❓ 4. Likely Viva / Examiner Questions & Answers

### Q1: "What is Shannon Entropy and why did you use it?"
> **Answer:**
> *"Shannon Entropy is a mathematical formula from information theory that measures the unpredictability or randomness of characters in a string:*
> $$H(X) = -\sum P(x_i) \log_2 P(x_i)$$
> *Normal English domain names (like `google.com` or `amazon.com`) have repeating vowels and patterns, giving an entropy between 2.0 and 3.5.*
> *Malware and automated phishing kits use DGAs (Domain Generation Algorithms) to create disposable random domains (like `x8q1-z9v2b.xyz`), which have high entropy (> 3.8). My system calculates this to detect algorithmic phishing domains."*

---

### Q2: "What is a Homoglyph or Typosquatting attack?"
> **Answer:**
> *"A homoglyph attack exploits characters that look visually identical to the human eye but have different ASCII/Unicode representations. For example, replacing letter 'o' with number '0' (like `micros0ft`), or replacing letter 'l' with number '1' (like `paypa1`), or using `rn` to look like `m` (`arnazon`). Humans don't notice it, but our system normalizes and maps these substitutions against a brand database."*

---

### Q3: "What are SPF, DKIM, and DMARC?"
> **Answer:**
> *"They are the three main email authentication standards:*
> 1. *SPF specifies which mail server IP addresses are authorized to send email for a domain.*
> 2. *DKIM adds a cryptographic digital signature to the email header to prove the content was not altered in transit.*
> 3. *DMARC tells the recipient server what to do (none, quarantine, or reject) if SPF or DKIM fail."*

---

### Q4: "Can your system detect zero-day phishing links?"
> **Answer:**
> *"Yes, because our system does **not** rely solely on fixed blacklists. It uses **heuristic behavioral analysis** — examining protocol security, entropy, subdomain depth, keyword clustering, and brand mismatch. Even if a phishing domain was registered 5 minutes ago and isn't on any blacklist yet, our heuristic engine flags it based on its structural properties."*

---

### Q5: "What technologies did you use to build this?"
> **Answer:**
> *"The backend detection engine is written in **Python**, using standard libraries (`re`, `math`, `urllib.parse`) for speed and zero external API dependencies. The interactive interface is built with **Streamlit** and styled with custom cybersecurity CSS."*
