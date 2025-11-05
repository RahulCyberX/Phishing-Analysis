# #66: The Greenholt Phish ⚔️

A Sales Executive at Greenholt PLC received an email that he didn't expect to receive from a customer. He claims that the customer never uses generic greetings such as "Good day" and didn't expect any amount of money to be transferred to his account. The email also contains an attachment that he never requested. He forwarded the email to the SOC (Security Operations Center) department for further investigation.

Investigate the email sample to determine if it is legitimate.

![image.png](image.png)

# Deploy the Machine

Deploy the machine attached to this task; it will be visible in the split-screen view once it is ready.

If you don't see a virtual machine automatically appear, click the Show Split View button.

**Tip**: Open the EML file with Thunderbird. To do so, **right-click** on the `challenge.eml` file and select **Open With Other Application**. From there, scroll down to select **Thunderbird Mail** and click **Open**. It may take a few moments to open the application. You will then see the email and its contents appear in the app.

![image.png](image%201.png)

Room Link: https://tryhackme.com/room/phishingemails5fgjlzxc

## Answer the questions below

### What is the **Transfer Reference Number** listed in the email's **Subject**?

- Can be found in the mail subject after opening it with Thunderbird.
    
    ![image.png](image%202.png)
    

Answer: `09674321`

### Who is the email from?

![image.png](image%203.png)

Answer: `Mr. James Jackson`

### What is his email address?

![image.png](image%204.png)

Answer: `info@mutawamarine.com`

### What email address will receive a reply to this email?

![image.png](image%205.png)

Answer: `info.mutawamarine@mail.com`

### What is the Originating IP?

- View the source code of the email.
    
    ![image.png](image%206.png)
    
- Look for the **from** inside **X-Originating-IP** section:
    
    ![image.png](image%207.png)
    

Answer: `192.119.71.157`

### Who is the owner of the Originating IP? (Do not include the "." in your answer.)

- Open **Whois Domain Lookup** from this link: https://www.whois.com/whois/
- Enter the originating IP:
    
    ![image.png](image%208.png)
    
    ![image.png](image%209.png)
    

Answer: `Hostwinds LLC`

### What is the SPF record for the Return-Path domain?

- To get the SPF record, open **MXToolBox**: https://mxtoolbox.com/SuperTool.aspx
- In the search box, paste the domain.
    
    ![image.png](image%2010.png)
    
    Choose the **SPF Record Lookup**:
    
    ![image.png](image%2011.png)
    
    ![image.png](image%2012.png)
    
    So this is what I got:
    
    - `v` = spf1
    - `include` = spf.protection.outlook.com
    - `all`

Answer: `v=spf1 include:spf.protection.outlook.com -all`

### What is the DMARC record for the Return-Path domain?

- To get DMARC record for this domain name, go to this link: https://dmarcian.com/dmarc-inspector/
- Enter the domain value `mutawamarine.com`
    
    ![image.png](image%2013.png)
    
    ![image.png](image%2014.png)
    

Answer: `v=DMARC1; p=quarantine; fo=1`

### What is the name of the attachment?

- In the email, there’s an attachment which we can see at the bottom.
    
    ![image.png](image%2015.png)
    

Answer: `SWT_#09674321____PDF__.CAB`

### What is the SHA256 hash of the file attachment?

This is easy.

- Download the attachment in your Desktop.
    
    ![image.png](image%2016.png)
    
- Run the following command in terminal.
    
    ```
    sha256sum SWT_#09674321____PDF__.CAB
    ```
    
    ![image.png](image%2017.png)
    

Answer: `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`

### What is the attachments file size? (Don't forget to add "KB" to your answer, **NUM KB**)

- Open VirusTotal: https://www.virustotal.com/gui/
- Paste the Hash Value from previous answer.
    
    ![image.png](image%2018.png)
    
    ![image.png](image%2019.png)
    

Answer: `400.26 KB`

### What is the actual file extension of the attachment?

![image.png](image%2020.png)

Answer: `rar`

---

![image.png](image%2021.png)