# #61: Phishing Emails in Action ⚔️

@Learn the different indicators of phishing attempts by examining actual phishing emails.

![image.png](image.png)

Now that we covered the basics concerning emails in [Phishing Emails 1](http://tryhackme.com/jr/phishingemails1tryoe), let's dive right into actual phishing email samples.

Each email sample showcased in this room will demonstrate different tactics used to make the phishing emails look legitimate. The more convincing the phishing email appears, the higher the chances the recipient will click on a malicious link, download and execute the malicious file, or even send the prince of some country a wire transfer.

**Warning:** The samples throughout this room contain information from actual spam and/or phishing emails. Proceed with caution if you attempt to interact with any IP, domain, attachment, etc.

Room Link: https://tryhackme.com/room/phishingemails2rytmuv

---

# Task 2: Cancel your PayPal order

**Techniques shown in this email sample**

- Spoofed email address
- URL shortening service
- HTML used to impersonate a legitimate brand (PayPal)

**Quick observations**

![image.png](image%201.png)

- Recipient address is unusual and **does not match** the Yahoo account — obvious red flag.
- `service@paypal.com` (displayed sender) **does not match** actual sender `gibberish@sultanbogor.com` — spoofing.
- Subject suggests a purchase/transaction to create **urgency** and prompt interaction.

**Email body**

![image.png](image%202.png)

- Designed to look like an official PayPal message (HTML impersonation).
- No attachments.
- Single interactive element: **“Cancel the order”** button/link.
    
    ![image.png](image%203.png)
    

**Hyperlink analysis**

![image.png](image%204.png)

- The link uses a **URL shortener** — dangerous without expanding first.
- When expanded via an online tool, the shortened link **redirects to google.com**.
    
    ![image.png](image%205.png)
    

**Note**

- Tools and methods to expand shortened URLs will be covered later (Phishing Emails 3).

## Answer the questions below

### What phrase does the gibberish sender email start with?

Answer: `noreply`

---

# Task 3: Track your package

**Techniques shown in this email sample**

- Spoofed email address
- Pixel tracking
- Link manipulation

**Quick observations**

![image.png](image%206.png)

- Email appears to come from a **fake mail distribution center**.
- **Subject line** includes a tracking number to look convincing.
- Link in the **email body matches** the fake tracking theme.

**Important note**

- Yahoo **blocked images** from auto-loading — a security measure to prevent pixel tracking.
- Hovering over the link doesn’t reveal its destination since **Yahoo disabled clickable links** for safety.

**Email hyperlink analysis**

![image.png](image%207.png)

- The source code shows an image named **Tracking.png**, which is actually a **tracking pixel**.
- Tracking pixels secretly **send data back to the spammer’s server** (e.g., confirming if the user opened the email).

**Conclusion**

- Yahoo blocked the images because **tracking pixels are commonly used by spammers**.
- The hyperlink points to a **shady, suspicious domain**, likely related to **malware distribution**.

## Answer the questions below

### What is the root domain for each URL? Defang the URL.

Answer: `devret[.]xyz`

---

# Task 4: Select your email provider to view document

**Techniques shown in sample**

- Urgency
- HTML impersonation of legitimate brands (OneDrive / Adobe / SharePoint)
- Link manipulation / redirects
- Credential harvesting (phishing form that captures credentials)
- Poor grammar / typos

**Quick observations**

![image.png](image%208.png)

- Sent date: **Thursday, July 15, 2021**.
- Uses **urgency**: download link expires same day to pressure action.
- Victim clicks a “download fax” button → **redirected to a fake OneDrive page** (URL is **not** Microsoft-related).
- Page contains two buttons; either leads to another site crafted to **resemble Adobe**.
    
    ![image.png](image%209.png)
    
- Victim prompted to **sign in with an email provider**; victim chose **Outlook**.
    
    ![image.png](image%2010.png)
    
    Tab title “Share Point Online”, which is a Microsoft product is shown to add legitimacy.
    
- Entered credentials are **captured by the attacker** (fake authentication—error shown regardless of credentials).
    
    ![image.png](image%2011.png)
    
- Multiple **grammatical errors** present (indicator of phishing).
- Sample source: **Any.Run** (analysis available at the link below).
    
    Analysis: https://app.any.run/tasks/12dcbc54-be0f-4250-b6c1-94d548816e5c/#
    

## Answer the questions below

### This email sample used the names of a few major companies, their products, and logos such as OneDrive and Adobe. What other company name was used in this phishing email?

![image.png](image%2012.png)

Answer: `citrix`

---

# Task 5: Please update your payment details

---

**This email sample will highlight the following techniques:**

- Spoofed email address
- Urgency
- HTML to impersonate a legitimate brand
- Poor grammar and/or typos
- Attachments

**Here are some quick observations about this email sample:**

- The email is made to appear from **Netflix Billing**, but the sender address is [**z99@musacombi.online**](mailto:z99@musacombi.online) (spoofed/mismatched sender).
- The message includes **urgency**: the account was **suspended**, prompting immediate action.
- The email body reinforces the **sense of urgency**.
    
    ![image.png](image%2013.png)
    
- The body contains multiple **misspellings of “Netflix”** (typos); resembles typosquatting-like errors but no actual typosquatting here.
    
    ![image.png](image%2014.png)
    
- The main instruction: the victim must **open the attached PDF** to update their Netflix account.
    
    ![image.png](image%2015.png)
    
- The email lists a **phone number for “Netflix”** that is unusual for a US-based recipient.
    
    ![image.png](image%2016.png)
    
- The attachment contains an **embedded link titled “Update Payment Account”**.
- Further attachment analysis will be covered in upcoming room.

## Answer the questions below

### What should users do if they receive a suspicious email or text message claiming to be from Netflix?

Article Link: https://www.consumeraffairs.com/news/police-warn-of-new-netflix-email-phishing-scam-121718.html

![image.png](image%2017.png)

Answer: `forward the message to phishing@netflix.com`

---

# Task 6: Your recent purchase

This email sample will highlight the following techniques:

- Spoofed email address
- Recipient is BCCed
- Urgency
- Poor grammar and/or typos
- Attachments

**Here are some quick observations about this email sample:**

- The email is made to appear from **Apple Support**, but the sender's address is [**gibberish@sumpremed.com**](mailto:gibberish@sumpremed.com) (spoofed).
- The email was **BCCed** (not sent directly to the victim’s inbox); the recipient address looks like another **spoofed Apple-style** email.
- The message conveys **urgency** — action is required from the victim.
    
    ![image.png](image%2018.png)
    
- Noticeable **typos** in sender/recipient addresses: **donoreply** and **payament**.
- The email has **no body** — it’s blank and **only contains an attachment**.
    
    ![image.png](image%2019.png)
    
- Attachment type: **.DOT** (Microsoft Word template file).
- The attachment contains a **large image** made to resemble an **App Store receipt**.
    
    ![image.png](image%2020.png)
    
- The embedded link in the attachment includes **Apple-related keywords** such as **apps** and **ios**.
    
    ![image.png](image%2021.png)
    

## Answer the questions below

### What does BCC mean?

![image.png](image%2022.png)

Answer: `Blind Carbon Copy`

### What technique was used to persuade the victim to not ignore the email and act swiftly?

Answer: `urgency`

---

# Task 7: DHL Express Courier Shipping notice

**This email sample will highlight the following techniques:**

- Spoofed email address
- HTML to impersonate a legitimate brand
- Attachments

**Here are some quick observations about this email sample:**

- The sender's email **doesn't match** the company being impersonated (**DHL**).
- The **subject line** implies there is a package DHL will ship for you.
- The **HTML** in the email body was designed to **look like it was sent from DHL**.
    
    ![image.png](image%2023.png)
    
- The source code shows the "view the email as a web page" link **doesn't contain an actual destination URL**.
    
    ![image.png](image%2024.png)
    
    ![image.png](image%2025.png)
    
- The only interactive element is the **email attachment** (an **Excel** document).
    
    ![image.png](image%2026.png)
    
- The attachment content is shown.
    
    ![image.png](image%2027.png)
    
- The attachment **runs a payload that throws an error**.
    
    ![image.png](image%2028.png)
    

## Answer the questions below

### What is the name of the executable that the Excel attachment attempts to run?

![image.png](image%2029.png)

Answer: `regasms.exe`

---

# Conclusion

In this room, I analyzed various **phishing email samples**, each demonstrating different or overlapping techniques.

Some emails reused common tactics like **spoofed addresses, urgency, and fake branding**, while others introduced **new tricks** such as **pixel tracking** or **BCC recipients**.

The key takeaway:

- **Detecting phishing emails requires strong awareness and consistent training.**

**Additional Resources to Learn More:**

- https://www.knowbe4.com/phishing
- https://www.itgovernance.co.uk/blog/5-ways-to-detect-a-phishing-email
- https://cheapsslsecurity.com/blog/10-phishing-email-examples-you-need-to-see/
- https://phishingquiz.withgoogle.com/

---

![image.png](image%2030.png)

---