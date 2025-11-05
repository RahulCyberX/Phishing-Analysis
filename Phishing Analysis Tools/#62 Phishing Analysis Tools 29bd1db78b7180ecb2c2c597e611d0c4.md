# #62: Phishing Analysis Tools

@Learn the tools used to aid an analyst to investigate suspicious emails.

Remember from [Phishing Room 1](https://tryhackme.com/room/phishingemails1tryoe); we covered how to manually sift through the email raw source code to extract information.

![image.png](image.png)

In this room, we will look at various tools that will aid us in analyzing phishing emails. We will:

- Look at tools that will aid us in examining email header information.
- Cover techniques to obtain hyperlinks in emails, expand the URLs if they're URL shortened.
- Look into tools to give us information about potentially malicious links without directly interacting with a malicious link.
- Cover techniques to obtain malicious attachments from phishing emails and use malware sandboxes to detonate the attachments to understand further what the attachment was designed to do.

Warning: The samples throughout this room contain information from actual spam and/or phishing emails. Proceed with caution if you attempt to interact with any IP, domain, attachment, etc.

Room Link: https://tryhackme.com/room/phishingemails3tryoe

---

# What information should we collect?

### **From the Email Header, collect:**

- **Sender Email Address**
- **Sender IP Address**
- **Reverse Lookup** of the sender’s IP
- **Email Subject Line**
- **Recipient Email Address** (including **CC/BCC** if applicable)
- **Reply-To Email Address** (if present)
- **Date/Time** the email was sent

### **From the Email Body & Attachments, collect:**

- **All URLs** (if a URL shortener is used, **expand** to find the real destination)
- **Attachment Name(s)**
- **Attachment Hash Value** (preferably **SHA256**, otherwise **MD5**)

---

⚠️ **Warning:**

Never click on any links or open attachments in the suspicious email.

Always handle analysis **cautiously and safely.**

---

# Email header analysis

**Tools for Extracting Header Info**

- Some header details (e.g., **sender IP**, **Reply-To**) are only visible in the **raw email header**, not the normal mail UI.
- Manually reading the raw source works, but tools speed things up.
- **Google Admin Toolbox - Messageheader**:
    - Purpose: **Analyze SMTP message headers** to identify delivery issues, misconfigured servers, and mail-routing problems.
    - Usage: **Copy & paste the entire email header** into the tool and run the analysis.
    - **Messageheader**: https://toolbox.googleapps.com/apps/messageheader/analyzeheader
    
    ![image.png](image%201.png)
    
- Another tool is called **Message Header Analyzer**.
    
    Link: https://mha.azurewebsites.net/
    
    ![image.png](image%202.png)
    
- Lastly, we can also use [mailheader.org](https://mailheader.org/).
    
    ![image.png](image%203.png)
    

**Tools for Analyzing Sender’s IP & URLs**

- **MTA (Message Transfer Agent):** Software responsible for transferring emails between sender and recipient.
- **MUA (Mail User Agent):** The email client used by the end user to read and send emails.

> Tip: Use multiple tools - each can reveal different insights during analysis.
> 

---

### **IP & URL Analysis Tools**

**1. [IPinfo.io](https://ipinfo.io/)**

![image.png](image%204.png)

- Purpose: Provides detailed info about an IP address.
- Features:
    - Pinpoints user locations.
    - Detects and prevents fraud.
    - Ensures compliance and enriches investigations.

---

**2. [URLScan.io](https://urlscan.io/)**

![image.png](image%205.png)

- Purpose: Scans and analyzes URLs safely.
- Features:
    - Simulates a real browser visit and records all network activity.
    - Captures **domains, IPs, resources (JS, CSS, cookies, etc.)**.
    - Takes a **screenshot** of the page - so you don’t visit it directly.
    - Flags URLs that mimic over 400+ tracked brands as **potentially malicious**.

---

**3. Alternative Tools**

- **URL2PNG** – Generates screenshots of URLs safely.
- **Wannabrowser** – Emulates browser access for safer link inspections.

---

**4. [Talos Reputation Center](https://talosintelligence.com/reputation)**

![image.png](image%206.png)

- Purpose: Cisco’s intelligence platform to check **IP/domain reputation**.
- Helps determine if an address or domain is **trusted, suspicious, or malicious**.

## Answer the questions below

### What is the official site name of the bank that capitai-one.com tried to resemble?

![image.png](image%207.png)

Answer: `capitalone.com`

---

# Email body analysis

**Analyzing the Email Body (Links & Attachments)**

Once the email header analysis is complete, the next focus is the **email body**, where malicious payloads are often hidden as **links or attachments**.

### **Extracting and Analyzing Links**

**Manual Method:**

- Right-click a hyperlink in the email → choose **“Copy Link Location”**.
    
    ![image.png](image%208.png)
    
    ![image.png](image%209.png)
    
- You can also extract links from the **HTML source** or raw header.

**Automated Tools:**

**1. [URL Extractor](https://www.convertcsv.com/url-extractor.htm)**

- Copy and paste the **raw email header** into the Step 1 input box.
    
    ![image.png](image%2010.png)
    
- Extracted URLs appear in **Step 3** automatically.
    
    ![image.png](image%2011.png)
    

**2. [CyberChef](https://gchq.github.io/CyberChef/)**

- Use the **“Extract URLs”** recipe to find all embedded links quickly.
    
    ![image.png](image%2012.png)
    

> Tip: Always note the root domain (e.g., example.com) for deeper reputation analysis.
> 

---

### **Checking URL and Domain Reputation**

Use tools like:

- **URLScan.io**
- **Talos Reputation Center**
- **IPinfo.io**

These help confirm whether a link or its domain is **trusted, suspicious, or malicious**.

---

### **Analyzing Attachments Safely**

**Step 1:** Save the attachment safely (e.g., via **Thunderbird → Save button**).

![image.png](image%2013.png)

**Step 2:** Generate its **SHA256 hash**:

```bash
sha256sum Double\ Jackpot\ Slots\ Las\ Vegas.dot
```

Example output:

```
c650f397a9193db6a2e1a273577d8d84c5668d03c06ba99b17e4f6617af4ee83  Double Jackpot Slots Las Vegas.dot
```

**Step 3:** Check the hash reputation using the tools below.

---

### **File Reputation Analysis Tools**

**1. [Talos File Reputation](https://talosintelligence.com/talos_file_reputation)**

![image.png](image%2014.png)

![image.png](image%2015.png)

- Maintains reputation on **billions of files**.
- Used by Cisco AMP, FirePower, ClamAV, and Snort.
- Supports **hash-based lookups** (one at a time).

**2. [VirusTotal](https://www.virustotal.com/gui/)**

![image.png](image%2016.png)

![image.png](image%2017.png)

- Scans suspicious files and URLs for malware.
- Automatically shares results with the global security community.

**3. [ReversingLabs](https://www.reversinglabs.com/)**

- Offers advanced **file reputation and malware intelligence** services.

---

## Answer the questions below

### How can you manually get the location of a hyperlink?

![image.png](image%2018.png)

Answer: `Copy Link Location`

---

# Malware Sandbox

**Malware Sandboxes**

- Defenders **don’t need deep malware-reversing skills** to learn what a malicious attachment does.
- **Malware sandboxes** are online services where you upload suspicious files to observe behavior (network calls, dropped payloads, persistence, IOCs, etc.).

**Example sandboxes listed:**

1. **Any.Run** — Interactive analysis; can interact with the OS from a browser and see immediate feedback.
    
    Link: https://app.any.run/
    
    ![image.png](image%2019.png)
    
2. **Hybrid Analysis** — Free community service that detects and analyzes unknown threats via hybrid analysis technology.
    
    Link: https://www.hybrid-analysis.com/
    
    ![image.png](image%2020.png)
    
3. **Joe Sandbox (joesecurity.org)** — Advanced features: live interaction, URL analysis, AI phishing detection, YARA/Sigma support, MITRE ATT&CK mapping, mail monitor, dynamic instrumentation, execution graphs, localized anonymization, etc.
    
    Link: https://www.joesecurity.org/
    
    ![image.png](image%2021.png)
    

Note: These sandboxes will be used in upcoming Phishing cases.

---

# PhishTool

**PhishTool (Automated Phishing Analysis)**

- **PhishTool** is a **phishing response and analysis platform** that combines:
    - Threat intelligence
    - OSINT
    - Email metadata
    - Automated analysis workflows
        
        → Making it useful for SOC analysts, researchers, and investigators.
        
- **Free community edition** available for download.

---

### Key Features Demonstrated:

![image.png](image%2022.png)

- Automatically extracts **core email details**:
    - Sender & recipient (including CC list)
    - Timestamp
    - Originating IP & reverse DNS lookup
        
        ![image.png](image%2023.png)
        
    - SMTP relay hops (e.g., Hop 1 of 6)
        
        ![image.png](image%2024.png)
        
    - X-header and Return-Path details
- Provides **email body views**:
    - *Text format*
        
        ![image.png](image%2025.png)
        
    - *HTML source*
        
        ![image.png](image%2026.png)
        
- Displays **attachments and URLs** in dedicated panes:
    - URLs: shows extracted links (none found in this sample)
        
        ![image.png](image%2027.png)
        
    - Attachments: shows filename and hash (ZIP file in this case)
        
        ![image.png](image%2028.png)
        

---

### VirusTotal Integration:

- Connected via **community edition API key** for automatic feedback.
- Shows attachment hash results directly in PhishTool.
- Allows manual lookup in VirusTotal for deeper analysis.

---

### Analyst Actions:

- View attachment **strings** and **VirusTotal results**.
    
    ![image.png](image%2029.png)
    
    ![image.png](image%2030.png)
    
- Mark files or hashes as **malicious**.
    
    ![image.png](image%2031.png)
    
- Click **Resolve** to close the case.
    
    ![image.png](image%2032.png)
    
- Assign **classification codes** (e.g., *Whaling* for high-value targets).
    
    ![image.png](image%2033.png)
    

---

**In short:**

PhishTool streamlines phishing investigations by collecting metadata, analyzing attachments safely, integrating with VirusTotal, and allowing analysts to document and classify incidents efficiently.

## Answer the questions below

### Look at the Strings output. What is the name of the EXE file?

![image.png](image%2034.png)

Answer: `#454326_PDF.exe`