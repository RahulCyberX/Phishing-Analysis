# #60: Phishing Analysis Fundamentals ⚔️

### Spam & Phishing Overview

![image.png](image.png)

- **Social Engineering Attacks:** Both spam and phishing rely on deceiving users — mainly through **emails**, but can also use **calls or texts**.
- **Spam:** Unwanted or junk emails; the first spam email appeared in **1978** and still persists today.
- **Phishing:** Malicious emails that trick users into clicking links or opening attachments to **steal data** or **infect systems**.
- **Risk Factor:** Even with strong defenses, **one careless user** clicking a bad link can compromise the entire network.
- **Security Analyst’s Role:**
    - Analyze suspicious emails and headers.
    - Identify if the email is **malicious or safe**.
    - Use gathered information to **update security tools** and **block similar future threats**.

Room Link: https://tryhackme.com/room/phishingemails1tryoe

---

# Task 2: The Email Address

### Email Basics

- **Inventor:** *Ray Tomlinson* — created the concept of email and popularized the **@ symbol** in the **1970s** for **ARPANET**.
- **Email Structure:**
    - **User Mailbox (Username):** Identifies the specific recipient (e.g., `billy`).
    - **@ Symbol:** Separates user and domain.
    - **Domain:** Identifies the mail server (e.g., `johndoe.com`).
- **Example:** `billy@johndoe.com`
    - User Mailbox → `billy`
    - Domain → `johndoe.com`
- **Analogy:**
    - **Street name = Domain**
    - **House number + recipient name = User mailbox**
        
        → Helps the “postal worker” (mail server) deliver emails correctly.
        

## Answer the questions below

### Email dates back to what time frame?

Answer: `1970s`

---

# Task 3: Email Delivery

### Email Transmission Protocols

When you hit **SEND**, several protocols work together to deliver your message.

### **1. SMTP (Simple Mail Transfer Protocol)**

- Handles **sending** emails from the client to the mail server or between servers.

### **2. POP3 (Post Office Protocol v3)**

- Used for **receiving** emails.
- **Emails are downloaded** and stored on **one device**.
- **Sent emails** stay on that device.
- Emails can only be accessed from **that single device** unless “Keep email on server” is enabled.

### **3. IMAP (Internet Message Access Protocol)**

- Also used for **receiving** emails.
- Emails are **stored on the server**, accessible from **multiple devices**.
- Sent messages are stored on the **server**.
- All devices stay **synced** with the same mailbox view.

**In short:**

- **SMTP → Sending**
- **POP3 → One-device access**
- **IMAP → Multi-device sync**

Next, we’ll see how an email travels from the **sender** to the **recipient**.

To best illustrate this, see the oversimplified image below:

![image.png](image%201.png)

### How an Email Travels from Sender to Recipient

1. **Composing the Email** –
    
    Alexa writes an email to [**billy@johndoe.com**](mailto:billy@johndoe.com) and hits **Send**.
    
2. **SMTP Server Queries DNS** –
    
    Alexa’s **SMTP server** checks **DNS** to find where to deliver the email (mail server for johndoe.com).
    
3. **DNS Responds** –
    
    The **DNS server** returns the mail exchange (MX) details for **johndoe.com** to the SMTP server.
    
4. **Email Transmission Begins** –
    
    The SMTP server starts sending Alexa’s email across the **Internet** toward Billy’s domain.
    
5. **SMTP Relaying** –
    
    The email passes through **multiple SMTP servers** until it reaches the **destination mail server**.
    
6. **Arrival at Destination Server** –
    
    The email finally lands at **johndoe.com’s SMTP server**.
    
7. **Stored for Delivery** –
    
    The message is transferred to the **POP3/IMAP server**, where it waits in Billy’s inbox.
    
8. **Recipient Login** –
    
    Billy logs into his **email client**, which connects to the **POP3/IMAP server** to check for new mail.
    
9. **Message Retrieved** –
    
    The email is either **downloaded (POP3)** or **synced (IMAP)** to Billy’s device.
    
10. **Ports in Use** –
- **SMTP:** 25 (sending)
- **POP3:** 110 (retrieving)
- **IMAP:** 143 (retrieving)

**Summary:**

Email flow = **SMTP (send) → DNS lookup → Mail servers → POP3/IMAP (receive)**

## Answer the questions below

### What port is classified as Secure Transport for SMTP?

Answer: `587`

### What port is classified as Secure Transport for IMAP?

- **Port:** 993
- **Purpose:** Retrieves and syncs emails securely from the server.

Answer: `993`

### What port is classified as Secure Transport for POP3?

- **Port:** 995
- **Purpose:** Downloads emails securely from the mail server to the client.

Answer: `995`

---

# Task 4: Email Headers

### Understanding Email Components & Headers

When analyzing an email — especially a **potentially malicious one** — it’s essential to understand how an email is structured and what hidden details lie within its **headers**.

---

## Two Main Parts of an Email

1. **Email Header**
    - Contains metadata (technical info about the email).
    - Reveals where it came from, which servers handled it, and who sent/received it.
    - Useful for tracing spoofed or malicious emails.
2. **Email Body**
    - The actual **content** of the message (plain text or HTML).
    - May include links, attachments, or embedded code.

---

## Internet Message Format (IMF)

- Defines how email messages are structured.
- Follows **RFC 5322**, which specifies header and body separation.
- Syntax:
    
    ```
    Header Fields
    (blank line)
    Body
    ```
    

---

## Common Email Header Fields (Visible in Most Clients)

![image.png](image%202.png)

| Header Field | Description |
| --- | --- |
| **From** | The sender’s email address. |
| **To** | The recipient’s email address. |
| **Subject** | The email’s title/summary. |
| **Date** | The timestamp when the email was sent. |

*These are what you usually see in your inbox UI (e.g., Gmail, Yahoo).*

---

## Viewing Raw Email Headers

- Every email client (web or desktop) has an option like **“View Raw Message”**, **“Show Original”**, or **“View Full Header.”**
    
    ![image.png](image%203.png)
    
- The raw header reveals *every step* the email took and all technical details (including hidden ones).

Example

![image.png](image%204.png)

---

## Important Hidden Header Fields

| Header | Meaning |
| --- | --- |
| **X-Originating-IP** | The sender’s IP address (can help trace the original source). |
| **SMTP.MailFrom / Header.From** | The domain the message was actually sent from (used in authentication checks). |
| **Reply-To** | The address replies are directed to (often used in phishing to divert replies). |

⚠️ **Example Attack Trick:**

- The **From** field shows a trusted domain (like PayPal).
- But the **Reply-To** or **Return-Path** points to a scammer’s domain.

---

## Example Breakdown (from `email1.eml` sample)

- **Sender:** `newsletters@ant.anki-tech.com`
- **Reply-To:** `reply@ant.anki-tech.com`
    - Meaning: If you click *Reply*, your message won’t go to the sender — it’ll go to a different email (`reply@ant.anki-tech.com`).

---

## Why Header Analysis Matters

When investigating **phishing or spam**, headers help you:

- Identify **spoofed domains** or **fake senders**.
- Check **server hops** (the path the email took).
- Detect **origin IPs** from unusual countries.
- Compare **Return-Path**, **From**, and **Reply-To** for inconsistencies.
- Validate **SPF/DKIM/DMARC** results under `Authentication-Results`.

---

### Reference (Required Reading)

**Media Temple – Understanding an Email Header:**

🔗 [Archived Link](https://web.archive.org/web/20221219232959/https://mediatemple.net/community/products/all/204643950/understanding-an-email-header)

**Note**: The questions below are based on the **Media Template** article.

## Answer the questions below

### What email header is the same as "Reply-to"?

![image.png](image%205.png)

Answer: `Return-Path`

### Once you find the email sender's IP address, where can you retrieve more information about the IP?

![image.png](image%206.png)

Answer: http://www.arin.net/

---

# Task 5: Email Body

### Understanding the Email Body

The **email body** is the main content of an email - what the sender actually wants you to read or see. It can appear in two formats:

---

## 1. Text-Only Emails

![image.png](image%207.png)

- Contain only **plain text** (no images, links, or formatting).
- Safest and simplest type — cannot execute malicious code.

---

## 2. HTML-Formatted Emails

![image.png](image%208.png)

- Use **HTML** to include:
    - Images
    - Hyperlinks
    - Styled text (colors, fonts, etc.)
- These can sometimes hide **malicious links or tracking elements**.

*Example:*

An email that looks like a professional “Netflix” message may contain hidden links or images to track clicks or deliver malware.

---

## Viewing Email HTML Source

You can view the **HTML code** of an email to see its true structure.

Steps vary by email client, but the concept is the same:

- **ProtonMail:** Use the option **“View source code”** to see the HTML code.
    
    ![image.png](image%209.png)
    
- **Other clients (Gmail, Yahoo, Outlook, etc.):** Look for options like “View Source” or “Show Original.”
- There’s also option to switch back to HTML, it is called "**View rendered HTML**" in **Protonmail**.
    
    ![image.png](image%2010.png)
    
- Viewing the source lets you inspect HTML code like:
    
    ![image.png](image%2011.png)
    

---

## Email Attachments

Emails can also include **attachments**, such as PDFs or ZIP files.

These are visible within the email body or in the HTML source code.

Example (from a Yahoo “Netflix” email):

![image.png](image%2012.png)

- The **email body** shows an image.
- There’s an **attached PDF file**.

When you view the email’s source, you’ll see extra headers describing the attachment:

![image.png](image%2013.png)

| Header | Description |
| --- | --- |
| **Content-Type:** `application/pdf` | Specifies the file type (PDF). |
| **Content-Disposition:** `attachment` | Confirms it’s an attachment, not inline content. |
| **Content-Transfer-Encoding:** `base64` | Indicates the file is base64 encoded. |

---

### Base64 Encoding

- Attachments in emails are often **base64 encoded** (text representation of binary data).
- You can **decode** this to recover the original file.
    
    ```bash
    base64 -d attachment.txt > decoded.pdf
    ```
    

⚠️ **Warning:**

Never double-click or open attachments from suspicious emails.

Malicious attachments may contain malware or scripts.

## Answer the questions below

### In the above screenshots, what is the URI of the blocked image?

![image.png](image%2014.png)

Answer: `https://i.imgur.com/LSWdDTi.png`

### In the screenshots above, what is the name of the PDF attachment?

![image.png](image%2015.png)

Answer: `Payment-updateid.pdf`

### In the attached virtual machine, view the information in email2.txt and reconstruct the PDF using the base64 data. What is the text within the PDF?

- Go to the folder containing **email2.txt**.
    
    ![image.png](image%2016.png)
    

---

- Open the file and copy only the B**ase64 Content**, its quite a lot.
- Create a new empty file, and I am gonna name it as answer.txt
    
    ```
    nano answer.txt
    ```
    
- Inside the editor, paste all the **Base64 Content** you copied from the **email2.txt** file.
    
    ![image.png](image%2017.png)
    
- Now **Decode the Base64 data** via the terminal
    
    ```
    base64 -d answer.txt > decoded.pdf
    ```
    
    After that is done, this pdf file will appear in the folder, openening it will reveal the text within the original encoded text file.
    
    ![image.png](image%2018.png)
    
    ![image.png](image%2019.png)
    

Answer: `THM{BENIGN_PDF_ATTACHMENT}`

---

# Task 6: Types of Phishing

Malicious emails can be categorized as:

- **Spam:** Bulk unsolicited junk emails.
- **MalSpam:** Malicious variant of spam.
- **Phishing:** Emails pretending to be from trusted entities to steal information.
- **Spear Phishing:** Targeted phishing aimed at specific individuals or organizations.
- **Whaling:** Phishing targeting high-level executives (e.g., CEO, CFO).
- **Smishing:** Phishing through text messages.
- **Vishing:** Phishing through voice calls.

### Common Phishing Characteristics

- Spoofed sender addresses.
- Urgent or alarming subject lines (e.g., “Invoice,” “Suspended”).
- Fake branding that mimics trusted companies.
- Poorly formatted or generic content (e.g., “Dear Sir/Madam”).
- Hidden or shortened malicious hyperlinks.
- Dangerous attachments disguised as documents.

### Safety Practice: Defanging

Defanging prevents accidental clicks by altering URLs or email addresses:

- Replace `.` → `[.]`
- Replace `@` → `[at]`
- Example:
    
    `http://www.suspiciousdomain.com` → `hxxp[://]www[.]suspiciousdomain[.]com`
    

Tool recommendation: **CyberChef** (for defanging and analysis).

**Scenario:**

Alexa (victim) forwards a suspicious email (`email3.eml`) to Billy (analyst) for investigation.

## Answer the questions below

### What trusted entity is this email masquerading as?

- Open the **email3.eml** file.
    
    ![image.png](image%2020.png)
    
- It will open in Thunderbird. After that click the “View source” button.
    
    ![image.png](image%2021.png)
    
- **The** **From**: field in the email header is:
    
    ![image.png](image%2022.png)
    
    ```
    From: =?UTF-8?B?VGhhbmsgeW91ISBIb21lIERlcG90?= <support@teckbe.com>
    ```
    
- The part between **=?UTF-8?B?** and **?=** is the Base64 encoded text.
    
    ```
    VGhhbmsgeW91ISBIb21lIERlcG90
    ```
    
- Using CyberChef to encode from Base64
    
    ![image.png](image%2023.png)
    
    Answer: `Home Depot`
    
    **Note:** Even without cyberchef it’s possible to decode this encoded text, via the terminal using the following command.
    
    ```
    echo "VGhhbmsgeW91ISBIb21lIERlcG90" | base64 -d
    ```
    

### What is the sender's email?

- In the source code page, in **Return Path** field.
    
    ![image.png](image%2024.png)
    
    Answer: `support@teckbe.com`
    

### What is the subject line?

![image.png](image%2025.png)

- **UTF-8** indicates the encoding format:
    
    ```
    Subject: =?UTF-8?B?T3JkZXIgUGxhY2VkIDogWW91ciBPcmRlciBJRCBPRDIzMjE2NTcwODkyOTEgUGxhY2VkIFN1Y2Nlc3NmdWxseQ==?=
    ```
    
- I used cyberchef to decode it, as the site was already opened.
    
    ![image.png](image%2026.png)
    
    Answer: `Order Placed: Your Order ID OD2321657089291 Placed Successfully`
    

### What is the website for the - CLICK HERE URL in a defanged format? (e.g. [https://website.thm](https://website.thm/))

- Search the source code for "**CLICK HERE**" text, locate the `href` link for this text.
    
    ![image.png](image%2027.png)
    
    ![image.png](image%2028.png)
    
    ```
    http://t.teckbe.com/p/?j3=3DEOowFcEwFHl6EOAyFcoUFVTVEchwFHlUFOo6lVTTDcATE7oUE7AUET=3D=3D">
    ```
    
    URLs can contain repeated or extra characters such as == at the end or unnecessary line breaks, be sure to remove them to get the correct path.
    
    **Cleaned version: (**`=3D` → `=` to get the actual URL)
    
    ```
    http://t.teckbe.com/p/?j3=EOowFcEwFHl6EOAyFcoUFVTVEchwFHlUFOo6lVTTDcATE7oUE7AUET==
    ```
    
- After this I used CyberChef to defang the URL.
    
    ![image.png](image%2029.png)
    
    Answer: `hxxp[://]t[.]teckbe[.]com/`
    

---

# Task 7: Conclusion

**BEC (Business Email Compromise):**

An attacker *gains control of an internal employee’s email account* and uses it to trick other employees into performing **unauthorised or fraudulent actions**.

**Room recap — topics covered:**

- Structure of an **email address** (user@domain).
- How an email **travels** from sender to recipient (SMTP, DNS, relays, POP3/IMAP).
- How to **view source** of an email **header**.
- How to **view source** of an email **body** (plain/HTML, attachments).
- Key **forensic fields** to extract when analysing an email.
- Common **attacker techniques** in spam/phishing campaigns (spoofing, urgency, malicious links/attachments).

### What is BEC?

Answer: `Business Email Compromise`

---

![image.png](image%2030.png)

---