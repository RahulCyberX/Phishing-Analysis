# #67: Snapped Phish-ing Line ⚔️

Apply learned skills to probe malicious emails and URLs, exposing a vast phishing campaign.

![image.png](image.png)

# Challenge Scenario

**Disclaimer:**

- Based on real-world occurrences and past analysis, this scenario presents a narrative with invented names, characters, and events.

**Please note:** The phishing kit used in this scenario was retrieved from a real-world phishing campaign. Hence, it is advised that interaction with the phishing artefacts be done only inside the attached VM, as it is an isolated environment.

![image.png](image%201.png)

Room Link: https://tryhackme.com/room/snappedphishingline

# An Ordinary Midsummer Day...

As an IT department personnel of SwiftSpend Financial, one of your responsibilities is to support your fellow employees with their technical concerns. While everything seemed ordinary and mundane, this gradually changed when several employees from various departments started reporting an unusual email they had received. Unfortunately, some had already submitted their credentials and could no longer log in.

You now proceeded to investigate what is going on by:

1. Analysing the email samples provided by your colleagues.
2. Analysing the phishing URL(s) by browsing it using Firefox.
3. Retrieving the phishing kit used by the adversary.
4. Using CTI-related tooling to gather more information about the adversary.
5. Analysing the phishing kit to gather more information about the adversary.

## Answer the questions below

### Who is the individual who received an email attachment containing a PDF?

- Open the folder which contains the phishing emails.
    
    ![image.png](image%202.png)
    
    The directory has 5 **.eml** files, and one of these emails contain a **pdf** attachment that I am looking for.  
    
    ![image.png](image%203.png)
    
- I can either open each email with Thunderbird to find if any of these emails contains the pdf attachment, or to save time I can use the following command to find name of attachment and file that contains it.
    
    ```
    grep "\.pdf” *.eml
    ```
    
    ![image.png](image%204.png)
    
- Now that the correct email is identified, open it with Thunderbird.
    
    ![image.png](image%205.png)
    
    ![image.png](image%206.png)
    

Answer: `William McClean`

### What email address was used by the adversary to send the phishing emails?

![image.png](image%207.png)

Answer: `Accounts.Payable@groupmarketingonline.icu`

### What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)

- Locate the email which was send **to** Zoe Duncan:
    
    ```
    grep “Zoe Duncan” *.eml
    ```
    
    ![image.png](image%208.png)
    
    I just realized that the filenames already contain the name of user the email was sent to.
    
    ![image.png](image%209.png)
    
- Open it with Thunderbird and download the attachment.
    
    ![image.png](image%2010.png)
    
- Now open terminal, and using **grep** I am gonna search for the redirection link.
    
    ```
    grep -i “redirect” Direct\ Credit\ Advice.html
    ```
    
    - I used `-i` because I am not sure about the capitalization.
    - `Direct\ Credit\ Advice.html` is basically referring to the “Direct Credit Advice.html” file.
    
    ![image.png](image%2011.png)
    
- Now that the link has been found open cyberchef to defang the url.
    
    ![image.png](image%2012.png)
    

Answer: `hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error`

### What is the URL to the .zip archive of the phishing kit? (defanged format)

- I checked the site root at `http://kennaroads.buzz` and noticed it’s a WordPress website.
    
    ![image.png](image%2013.png)
    
    ![image.png](image%2014.png)
    
- Then I removed the URL path which was appended for tricking the user and navigated to the `/data/Update365` path.
    
    ![image.png](image%2015.png)
    
    ![image.png](image%2016.png)
    
    It seems that this website is hosting some files. 
    
- Then from here, I went to the parent directory, to the `/data` path, and found the **.zip** file. This is the leaked phishing kit.
    
    ![image.png](image%2017.png)
    
- Copied the URL and defanged it in Cyberchef.
    
    ![image.png](image%2018.png)
    
    ![image.png](image%2019.png)
    

Answer: `hxxp[://]kennaroads[.]buzz/data/Update365[.]zip`

### What is the SHA256 hash of the phishing kit archive?

- I downloaded it with `wget` (carefully on the isolated host) and generated the hash.
    
    ![image.png](image%2020.png)
    
- Then ran the following command to generate **SHA256 hash** of this downloaded kit.
    
    ```
    sha256sum Update365.zip
    ```
    
    ![image.png](image%2021.png)
    

Answer: `ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686`

### When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

- To check this I open VirusTotal and paste the hash.
    
    ![image.png](image%2022.png)
    
- The **Details** tab includes the first submission date and date.
    
    ![image.png](image%2023.png)
    

Answer: `2020-04-08 21:55:50 UTC`

### When was the SSL certificate the phishing domain used to host the phishing kit archive first logged? (format: YYYY-MM-DD)

- In that wordpress website, there was no SSL certificate available which means it has expired.
- Opened the hint and found the answer.
    
    ![image.png](image%2024.png)
    

Answer: `2020-06-25`

### What was the email address of the user who submitted their password twice?

- To find this, I viewed it the `log.txt` file directly on the server because it was accessible.
    
    ![image.png](image%2025.png)
    
- Then downloaded this log file using `wget`.
    
    ```
    wget kennaroads.buzz/data/Update365/log.txt
    ```
    
    ![image.png](image%2026.png)
    
- Then I searched for keyword **Email** inside the `log.txt` file,
    
    ```
    grep -i Email log.txt 
    ```
    
    ![image.png](image%2027.png)
    
- To see how many times the same unique email was found:
    
    ```
    grep -i Email log.txt | sort | uniq -c
    ```
    
    ![image.png](image%2028.png)
    

Answer: `michael.ascot@swiftspend.finance`

### What was the email address used by the adversary to collect compromised credentials?

- I unzipped the kit (.zip) that I downloaded earlier and extracted it.
    
    ```
    unzip Update365.zip -d Update365
    ```
    
    ![image.png](image%2029.png)
    
- Then I kept going deeper inside the folder until I found the `submit.php` file.
    
    ![image.png](image%2030.png)
    
- I opened that file using `cat` and looked for the `$to` or `$send` variable or `mail()` calls.

![image.png](image%2031.png)

Answer: `m3npat@yandex.com`

### The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?

- In the current directory, I searched inside all the files for string `gmail.com`:
    
    ```
    grep gmail.com ./*
    ```
    
    ![image.png](image%2032.png)
    

Answer: `jamestanner2299@gmail.com`

### What is the hidden flag?

![image.png](image%2033.png)

- I tried navigating to the phishing URL.
    
    ![image.png](image%2034.png)
    
- So I navigated to the auto-generated endpoint `/data/update365/office365` and started guessing filenames appropriate for a flag that ends with `.txt`.
    
    ![image.png](image%2035.png)
    
- Guessed `/flag.txt`
    
    ![image.png](image%2036.png)
    
- Now inorder to decode it, I copied the secret key and opened terminal.
    
    ![image.png](image%2037.png)
    
    Then reversed it:
    
    ![image.png](image%2038.png)
    

Answer: `THM{pL4y_w1Th_tH3_URL}`

---

![image.png](image%2039.png)