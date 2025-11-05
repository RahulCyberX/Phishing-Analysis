# #64: Phishing Prevention

# Introduction to Phishing Defense

## Why Phishing Matters

Phishing is still one of the **most common and effective attack methods** used by threat actors to gain **initial access** into target systems.

It relies on **social engineering** — tricking users into revealing sensitive data or clicking malicious links.

![image.png](image.png)

## MITRE ATT&CK Reference

According to the **MITRE ATT&CK Framework**,

> Phishing for Information is an attacker’s attempt to deceive targets into divulging confidential information such as credentials, financial data, or personal details.
> 

This tactic falls under **TA0001: Initial Access**, where the goal is to gain entry into a victim’s network or account.

In this module, I’ll explore **how organizations defend against phishing** through a combination of prevention, detection, and mitigation techniques.

### Key Topics Covered:

1. **Preventive Controls** – Measures to block phishing attempts before they reach users.
2. **Detection Mechanisms** – Tools and processes to identify phishing attacks in real time.
3. **Mitigation Strategies** – Steps to respond and minimize the impact after a phishing attempt.

Room Link: https://tryhackme.com/room/phishingemails4gkxh

---

# Sender Policy Framework (SPF)

## What is SPF?

According to **Dmarcian**,

> “Sender Policy Framework (SPF) is used to authenticate the sender of an email. With an SPF record in place, Internet Service Providers (ISPs) can verify that a mail server is authorized to send email for a specific domain.”
> 

Essentially, SPF helps prevent **email spoofing** - attackers pretending to send emails from trusted domains.

## How SPF Works (Workflow)

![image.png](image%201.png)

1. **Sender** → sends an email.
2. **Recipient mail server** → checks the sender’s domain’s **SPF record** via DNS lookup.
3. Based on that record, the server **decides whether to accept, flag, or reject** the email.

**SPF Workflow:**

```
Email Sent → DNS Lookup → SPF Record Found → Verification Result → Action Taken
```

| **Verification Result** | **Intended Action** |
| --- | --- |
| Pass, Neutral, None | ✅ Accept (Allow and process the email) |
| SoftFail, PermError | ⚠️ Flag (Mark as suspicious but allow) |
| Fail, TempError | ❌ Reject (Immediately discard the email) |

## SPF Record

```
v=spf1 ip4:127.0.0.1 include:_spf.google.com -all
```

### Breakdown:

- **v=spf1** → Marks the start of the SPF record.
- **ip4:127.0.0.1** → Authorizes this IP (IPv4) to send mail.
- **include:_spf.google.com** → Authorizes Google’s SPF rules for this domain.
- **all** → Reject all other non-authorized sources.

## Example: TryHackMe’s SPF Record

Using **Dmarcian’s SPF Surveyor Tool**, TryHackMe’s SPF record shows three domains authorized to send emails:

![image.png](image%202.png)

```
_spf.google.com
email.chargebee.com
7168674.spf05.hubspotemail.net
```

No IP addresses appear directly - instead, SPF inherits all IPs defined by these domains.

This means **emails sent from any of these trusted domains are accepted as legitimate**.

## Useful Tools

- [**Dmarcian SPF Surveyor**](https://dmarcian.com/spf-surveyor/) — Visualize and verify SPF records’ syntax and validity.
- [**Google Admin Toolbox Messageheader**](https://toolbox.googleapps.com/apps/messageheader/) — Analyze full email headers to check SPF, DKIM, and DMARC results.

Example Output:

![image.png](image%203.png)

> SPF: SoftFail (IP Unknown)
> 
> 
> ➜ The sending mail server isn’t authorized, but the message is **accepted and flagged** as suspicious.
> 

## Answer the questions below

### Based on TryHackMe's SPF record above, how many domains are authorized to send email on its behalf?

Answer: `3`

### What is the intended action of an email that returns a `SoftFail` verification result?

Answer: `Flag`

---

# DomainKeys Identified Mail (DKIM)

## What is DKIM?

**DKIM (DomainKeys Identified Mail)** is an **email authentication protocol** that verifies that a message was **not altered in transit** and actually originated from the claimed domain.

According to **Dmarcian**,

> “DKIM stands for DomainKeys Identified Mail and is used for the authentication of an email that’s being sent. Like SPF, DKIM is an open standard for email authentication that is used for DMARC alignment. A DKIM record exists in the DNS, but it is more complex than SPF. DKIM’s advantage is that it can survive forwarding, which makes it superior to SPF and a foundation for securing your email.”
> 

## How DKIM Works (Workflow)

![image.png](image%204.png)

### Step-by-Step Process:

1. **Email Sent:**
    
    The sending mail server uses its **private key** to add a **digital signature** to the email header.
    
2. **Public Key Retrieval:**
    
    The receiving mail server looks up the **DKIM public key** from the sender’s **DNS record**.
    
3. **Signature Verification:**
    - If the public key matches the private key’s signature → ✅ Email is **authentic**.
    - If not → ⚠️ The email is flagged or rejected as potentially **tampered** or **spoofed**.

### Visual Summary:

```
Sender’s Private Key → Signs Email
↓
Receiver’s Mail Server → Retrieves Public Key from DNS
↓
Keys Match → Deliver
Keys Don’t Match → Flag/Reject
```

## DKIM Record Example

```
v=DKIM1; k=rsa; p=<public_key>
```

- **v=DKIM1** → Version of DKIM being used.
- **k=rsa** → Key type (RSA is standard).
- **p=** → Public key (used to verify the signature).

> DKIM records may include other tags depending on the mail provider or setup.
> 

---

## Tools for DKIM Validation

- [**Dmarcian DKIM Record Checker**](https://dmarcian.com/dkim-inspector/) — Validate and analyze DKIM records.
- [**DKIM Validator**](https://www.appmaildev.com/en/dkim) — Check your email’s DKIM, SPF, and DMARC authentication status.

## DKIM Verification Errors

A **PermError** (Permanent Error) in DKIM verification means that DKIM authentication **failed completely**.

![image.png](image%205.png)

### Possible Reasons:

- Invalid or **expired DKIM signature**
- **Missing or incorrect DNS** DKIM record
- **Email forwarding** modified message headers
- **Misconfigured DKIM setup** on sending server

For the example email header:

The **permerror** indicates that the DKIM signature could not be validated, possibly due to tampering or a configuration issue.

## Answer the questions below

### Based on the sample header above, what is the reason for the `permerror`?

![image.png](image%206.png)

Answer: `no key for signature`

---

# Domain-Based Message Authentication, Reporting, and Conformance (DMARC)

## What is DMARC?

**DMARC (Domain-Based Message Authentication, Reporting, and Conformance)** is an **open standard** that builds upon **SPF** and **DKIM** to ensure that email senders are truly who they claim to be.

According to *Dmarcian*:

> “DMARC, an open source standard, uses a concept called alignment to tie the result of two other open source standards — SPF (a published list of servers that are authorized to send email on behalf of a domain) and DKIM (a tamper-evident domain seal associated with a piece of email) — to the content of an email.”
> 

## How DMARC Works

DMARC checks that:

1. The **domain in the "From" address** matches the domain authenticated by **SPF** or **DKIM**.
2. If both or either of those checks fail, the **DMARC policy** determines how the recipient’s mail server should respond.

### Possible DMARC Policy Actions:

| **Verification Result** | **DMARC Policy (p=)** | **Action** |
| --- | --- | --- |
| Alignment Pass | none | Accept message normally |
| Alignment Fail | quarantine | Move email to spam/junk folder |
| Alignment Fail | reject | Completely block the email |

## Example of a DMARC Record

```
v=DMARC1; p=quarantine; rua=mailto:postmaster@website.com🔍:
```

- **v=DMARC1** → Version of DMARC (required).
- **p=quarantine** → Policy action; moves suspicious emails to spam folder.
- **rua=mailto:postmaster@website.com** → Optional tag; sends **aggregate reports** of authentication results to this address.

> Example policies:
> 
> - `p=none` → Monitor only, no blocking.
> - `p=quarantine` → Send failed emails to spam.
> - `p=reject` → Block failed emails entirely.

## Tool: Dmarcian Domain Checker

[**Dmarcian Domain Checker**](https://dmarcian.com/domain-checker/) inspects a domain’s:

- **DMARC record**
- **SPF record**
- **DKIM record**

It identifies configuration issues and shows whether all protections are properly aligned.

![image.png](image%207.png)

### Example — *microsoft.com*:

Passed all checks ✅ 

Policy: `p=reject` → Any email that fails DMARC alignment is **rejected outright** (blocked completely).

## Answer the questions below

### Which DMARC policy provides the greatest amount of protection by blocking emails that fail the DMARC check?

![image.png](image%208.png)

Answer: `p=reject`

---

# Secure/Multipurpose Internet Mail Extensions (S/MIME)

## What is S/MIME?

**S/MIME (Secure/Multipurpose Internet Mail Extensions)** is a **standard protocol** used for sending **digitally signed** and **encrypted** emails — ensuring privacy, authenticity, and data integrity between sender and receiver.

It’s widely used in enterprises and government organizations to secure email communication using **Public Key Cryptography**.

## Core Components & Security Features

### 1. **Digital Signatures**

Used to **authenticate** the sender and ensure message integrity.

- **Authentication:**
    
    Confirms the sender’s identity using a **digital certificate**.
    
- **Non-repudiation:**
    
    Prevents the sender from denying they sent the email.
    
- **Data Integrity:**
    
    Detects any changes or tampering after the message was signed.
    

*Think of it as the sender’s verified “stamp of authenticity.”*

### 2. **Encryption**

Used to **protect the confidentiality** of the message contents.

- **Confidentiality:**
    
    Keeps the message private — only the **intended recipient** can read it.
    
- **Data Integrity:**
    
    Detects unauthorized modifications during transmission.
    

*Encryption ensures no one can eavesdrop or read the message in transit.*

## How S/MIME Works (Using Public Key Cryptography)

Here’s a step-by-step look at how **Bob** and **Mary** securely exchange emails:

1. **Bob obtains a Digital Certificate**
    - The certificate contains **Bob’s public key**.
2. **Bob sends an email signed with his private key.**
    - This signature verifies that the message is truly from Bob.
3. **Mary receives the email**
    - She uses **Bob’s public key** (from his certificate) to verify the signature and decrypt any encrypted content.
4. **Mary replies to Bob**
    - She attaches her **own digital certificate** and signs/encrypts her reply.
5. **Future Communication**
    - Both now possess each other’s certificates, enabling **trusted, encrypted email exchanges**.

### Visual Summary (Public Key Cryptography Workflow)

![image.png](image%209.png)

## Answer the questions below

### Which S/MIME component ensures that only the intended recipient can read the contents of an email message?

![image.png](image%2010.png)

Answer: `Encryption`

---