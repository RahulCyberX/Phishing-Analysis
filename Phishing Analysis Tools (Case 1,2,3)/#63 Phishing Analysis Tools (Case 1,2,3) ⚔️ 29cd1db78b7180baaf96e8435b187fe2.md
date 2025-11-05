# #63: Phishing Analysis Tools (Case 1,2,3) ⚔️

# Phishing Case 1

**Scenario:** You are a Level 1 SOC Analyst. Several suspicious emails have been forwarded to you from other coworkers. You must obtain details from each email for your team to implement the appropriate rules to prevent colleagues from receiving additional spam/phishing emails.

![image.png](image.png)

**Task:** Use the tools discussed throughout this room (or use your own resources) to help you analyze each email header and email body.

## Answer the questions below

### What brand was this email tailored to impersonate?

- Open the project file in Thunderbird
    
    ![image.png](image%201.png)
    
- Based on the subject and From of this email, I think its clear which brand it is impersonating.
    
    ![image.png](image%202.png)
    

Answer: `Netflix`

### What is the From email address?

- Also pretty obvious.
    
    ![image.png](image%203.png)
    

Answer: `JGQ47wazXe1xYVBrkeDg-JOg7ODDQwWdR@JOg7ODDQwWdR-yVkCaBkTNp.gogolecloud.com`

### What is the originating IP? Defang the IP address.

- For this, click More and select View source option.
    
    ![image.png](image%204.png)
    
- Originating IP is shown above.
    
    ![image.png](image%205.png)
    
- I used cyberchef to defang the IP address.
    
    ![image.png](image%206.png)
    

Answer: `209[.]85[.]167[.]226`

### From what you can gather, what do you think will be a domain of interest? Defang the domain.

- The information should be present in the Relaying-Domain of the mail, as well as in the Return-Path
    
    ![image.png](image%207.png)
    

Answer (after defanging in cyberchef): `etekno[.]xyz`

### What is the shortened URL? Defang the URL.

- Because I need to find URL, I search the code for **href** keyword.
    
    ![image.png](image%208.png)
    
    I copied the URL.
    
- Opened Internet Explorer and it automatically loaded up the cyberchef homepage (from local file).
    
    ![image.png](image%209.png)
    
- Set the operation as **Defang URL** and paste the copied link in the input box.
    
    ![image.png](image%2010.png)
    

Answer: `hxxps[://]t[.]co/yuxfZm8KPg?amp==1`

---

# Phishing Case 2

**Scenario**: You are a Level 1 SOC Analyst. Several suspicious emails have been forwarded to you from other coworkers. You must obtain details from each email for your team to implement the appropriate rules to prevent colleagues from receiving additional spam/phishing emails.

A malicious attachment from a phishing email inspected in the previous Phishing Room was uploaded to Any Run for analysis.

**Task**: Investigate the analysis and answer the questions below.

**Link**: https://app.any.run/tasks/8bfd4c58-ec0d-4371-bfeb-52a334b69f59

## Answer the questions below

### What does AnyRun classify this email as?

- First open the provided **AnyRun** link.
- See the banner at top right, its the classification.
    
    ![image.png](image%2011.png)
    

Answer: `Suspicious Activity`

### What is the name of the PDF file?

- Pretty obvious.
    
    ![image.png](image%2012.png)
    

Answer: `Payment-updateid.pdf`

### What is the SHA 256 hash for the PDF file?

- Open the text report.
    
    ![image.png](image%2013.png)
    
- Locate the **SHA256** under General Info.
    
    ![image.png](image%2014.png)
    

Answer: `CC6F1A04B10BCB168AEEC8D870B97BD7C20FC161E8310B5BCE1AF8ED420E2C24`

### What two IP addresses are classified as malicious? Defang the IP addresses. (answer: **IP_ADDR,IP_ADDR**)

- Stay on the current Report Document tab.
- Click on network.
    
    ![image.png](image%2015.png)
    
- Scroll down while looking at their **Reputation** to locate the malicious IPs.
    
    ![image.png](image%2016.png)
    
    Now go to next connections page.
    
    ![image.png](image%2017.png)
    
    IPs we found:
    
    > 2.16.107.24:443
    2.16.107.83:443
    > 
- Now Defang both IP with cyberchief after removing the port number.
    
    ![image.png](image%2018.png)
    

Answer: `2[.]16[.]107[.]24,2[.]16[.]107[.]83`

### What Windows process was flagged as **Potentially Bad Traffic**?

![image.png](image%2019.png)

Answer: `svchost.exe`

---

# Phishing Case 3

**Scenario:** You are a Level 1 SOC Analyst. Several suspicious emails have been forwarded to you from other coworkers. You must obtain details from each email for your team to implement the appropriate rules to prevent colleagues from receiving additional spam/phishing emails.

A malicious attachment from a phishing email inspected in the previous Phishing Room was uploaded to Any Run for analysis.

**Task:** Investigate the analysis and answer the questions below.

**Link**: https://app.any.run/tasks/82d8adc9-38a0-4f0e-a160-48a5e09a6e83

## Answer the questions below

### What is this analysis classified as?

![image.png](image%2020.png)

Answer: `Malicious activity`

### What is the name of the Excel file?

![image.png](image%2021.png)

Answer: `CBJ200620039539.xlsx`

### What is the SHA 256 hash for the file?

- Click on Text report.
    
    ![image.png](image%2022.png)
    
    ![image.png](image%2023.png)
    

Answer: `5F94A66E0CE78D17AFC2DD27FC17B44B3FFC13AC5F42D3AD6A5DCFB36715F3EB`

### What domains are listed as malicious? Defang the URLs & submit answers in alphabetical order. (answer: **URL1,URL2,URL3**)

- Click on networks.
    
    ![image.png](image%2024.png)
    
- Locate the three malicious domains.
    
    ![image.png](image%2025.png)
    
- Defang them with cyberchef. (Format: URL1,URL2,URL3)
    
    ![image.png](image%2026.png)
    

Answer: `biz9holdings[.]com,findresults[.]site,ww38[.]findresults[.]site`

### What IP addresses are listed as malicious? Defang the IP addresses & submit answers from lowest to highest. (answer: **IP1,IP2,IP3**)

- Similar to previous one, just copy their IP addresses this time, and defang them with cyberchef.
    
    ![image.png](image%2027.png)
    
    ![image.png](image%2028.png)
    
- Based on the question statement, the correct answer should have been: **(IP1,IP2,IP3)**
    
    `204[.]11[.]56[.]48,103[.]224[.]182[.]251,75[.]2[.]11[.]242`
    
    But it’s wrong. The correct format is **IP3,IP2,IP1.**
    

Answer: `75[.]2[.]11[.]242,103[.]224[.]182[.]251,204[.]11[.]56[.]48`

### What vulnerability does this malicious attachment attempt to exploit?

![image.png](image%2029.png)

Answer: `cve-2017-11882`

---

# Conclusion

The tools covered in this room are just some that can help you with analyzing phishing emails.

As a defender, you'll come up with your own preferred tools and techniques to perform manual and automated analysis.

Here are a few other tools that we have not covered in detail within this room that deserve a shout:

- https://mxtoolbox.com/
- https://phishtank.com/
- https://www.spamhaus.org/

That's all, folks! Happy Hunting!

---

![image.png](image%2030.png)

---