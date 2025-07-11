# ¿Qué es un CTF y en qué me metí?

Este repositorio busca introducir a estudiantes y entusiastas al mundo de los CTF (Capture The Flag), competencias diseñadas para practicar y demostrar habilidades en ciberseguridad.

🔐 Aquí aprenderás desde qué es un CTF hasta cómo participar en uno, con ejemplos, guías y recursos prácticos.


## 📚 Contenido

1. ¿Qué es un CTF?
2. Tipos de CTF
3. Categorías comunes
4. Herramientas útiles
5. Primeros pasos
6. Laboratorios recomendados
7. Recursos externos
8. Ejemplos de desafíos

---

# 🚀 Recomendado para

- Estudiantes de informática, redes o seguridad.
- Cualquier persona que quiera aprender y entrar en el mundo de la ciberseguridad de una forma practica e interesante 
- Equipos estudiantiles que quieran aprender juntos.


Un CTF (Capture The Flag) es una competencia de ciberseguridad en la que los participantes deben resolver desafíos técnicos para encontrar una "flag" o bandera (una cadena de texto que sirve como prueba de que resolviste el reto).

Las flags suelen tener el formato `flag{algo_aqui}` y cada categoría representa un área del hacking ético o seguridad informática.

---

# 🎯 Objetivos

- Aprender técnicas reales de hacking ético
- Resolver problemas de seguridad en diferentes niveles
- Trabajar en equipo y desarrollar habilidades de análisis

# 📖 Glosario rápido de términos CTF

Una lista de términos comunes que encontrarás en competencias Capture The Flag (CTF), explicados de forma simple para principiantes.

| Término        | Definición breve                                                                   |
|----------------|-------------------------------------------------------------------------------------|
| **Flag**       | Cadena secreta que debes encontrar (formato típico: `flag{...}`)                   |
| **Exploit**    | Código o técnica usada para aprovechar una vulnerabilidad                          |
| **Payload**    | Información o código que se envía para ejecutar una acción en el objetivo          |
| **Shell**      | Acceso a una consola o terminal remota                                             |
| **Bruteforce** | Ataque de fuerza bruta para probar muchas combinaciones hasta acertar             |
| **Vulnerabilidad** | Falla o error de seguridad que puede ser aprovechado                         |
| **Diccionario**| Lista de palabras usada para romper contraseñas                                   |
| **Wordlist**   | Sinónimo de diccionario (muy usado en cracking)                                   |
| **SUID**       | Permiso especial en Linux que permite ejecutar un archivo como si fueras root      |
| **Reverse Shell** | Una shell que conecta de vuelta al atacante desde la máquina víctima          |

> ✨ Este glosario se irá actualizando con más términos a medida que avances en el mundo CTF.


# Categorías Comunes en CTF

| Categoría     | Descripción breve |
|---------------|-------------------|
| Web           | Ataques y fallos en sitios web (XSS, SQLi, etc.) |
| Forensics     | Análisis de archivos, memoria o tráfico |
| Crypto        | Criptografía y criptoanálisis básico |
| Pwn           | Explotación de binarios, buffer overflow |
| Reverse       | Ingeniería inversa de binarios y apps |
| OSINT         | Búsqueda de información en fuentes abiertas |
| Misc          | Reto libre o mezcla de habilidades |
| SCADA / OT    | Sistemas industriales, frecuentemente en competencias avanzadas |




##🔧 Comandos y conceptos claves para Kali Linux
#📁 Navegación básica

- ls           |# Lista archivos
- cd           |# Cambia de directorio
- pwd          |# Muestra el directorio actual
- cp, mv, rm   |# Copiar, mover, eliminar archivos

🧰 Herramientas típicas en CTF
📡 Red
Nmap
# 🛰️ Introducción a Nmap

## ¿Qué es Nmap?

**Nmap** (Network Mapper) es una herramienta de código abierto utilizada para **explorar redes**, **auditar seguridad** y **descubrir servicios disponibles** en máquinas remotas. Es uno de los programas más utilizados en el mundo del hacking ético y CTFs (Capture The Flag).

## ¿Para qué se usa?

Nmap permite:

- 📡 Descubrir hosts activos en una red.
- 🔎 Identificar puertos abiertos (TCP/UDP).
- 🧠 Detectar servicios y sus versiones (como HTTP, SSH, FTP).
- 🧬 Realizar fingerprinting del sistema operativo.
- 🧰 Ejecutar scripts para encontrar vulnerabilidades.
- 🛡️ Evaluar la superficie de ataque de un servidor.

## ¿Por qué es importante en CTF?

En competencias CTF, Nmap es **la herramienta de reconocimiento por excelencia**, ya que te permite:

- Ver **qué puertos están abiertos** en la máquina objetivo.
- Saber **qué servicios están corriendo** y potencialmente vulnerables.
- Obtener pistas valiosas para explotar un servicio o puerto específico.

> 🧠 *Piensa en Nmap como tu linterna en una red desconocida: ilumina el terreno antes de actuar.*

# 🛰️ Comandos útiles de Nmap

Esta tabla resume los comandos más usados en Nmap, clasificados por función. Ideal para principiantes en CTF.

| 🗂️ Categoría             | 🛠️ Opción Nmap             | 🧾 Descripción                                                      | 💡 Ejemplo                                                   |
|--------------------------|----------------------------|---------------------------------------------------------------------|--------------------------------------------------------------|
| Escaneo rápido           | `-sn`                      | Escaneo de ping (sin puertos)                                      | `nmap -sn 10.10.10.0/24`                                     |
| Escaneo por puertos      | `-p`, `-F`                 | Puertos específicos o escaneo rápido                               | `nmap -p 80,443 10.10.10.10`<br>`nmap -F 10.10.10.10`         |
| Todos los puertos        | `-p-`                      | Escanea del puerto 1 al 65535                                       | `nmap -p- 10.10.10.10`                                       |
| Detección de servicios   | `-sV`                      | Identifica versiones de servicios                                  | `nmap -sV 10.10.10.10`                                       |
| Detección de sistema op. | `-O`                       | Intenta adivinar el sistema operativo                              | `nmap -O 10.10.10.10`                                        |
| Uso de scripts NSE       | `-sC`, `--script`          | Ejecuta scripts predeterminados o personalizados                   | `nmap -sC 10.10.10.10`<br>`nmap --script=ftp* 10.10.10.10`    |
| Modo sigiloso/agresivo   | `-T0` a `-T5`              | Controla velocidad del escaneo (0=lento, 5=rápido)                 | `nmap -T4 10.10.10.10`                                       |
| Guardar resultado        | `-oN`, `-oX`, `-oG`        | Guarda salida en texto, XML o formato grep                         | `nmap -oN salida.txt 10.10.10.10`                            |
| Evadir detección         | `-D`, `-S`, `--spoof-mac`  | Técnicas para anonimato (decoys, IP/MAC falsos)                    | `nmap -D RND:10 IP`<br>`nmap --spoof-mac Apple 10.10.10.10`  |
| Escaneo UDP              | `-sU`                      | Escanea puertos UDP                                                | `nmap -sU -p 53,161 10.10.10.10`                             |
| Traceroute               | `--traceroute`             | Muestra el camino hasta el host objetivo                           | `nmap --traceroute 10.10.10.10`                              |
| Escaneo agresivo         | `-A`                       | Combina varios modos: `-O`, `-sC`, `-sV` y traceroute              | `nmap -A 10.10.10.10`                                        |

---

## 📌 Tips extra

- Combina `-sV` con `-p-` para detectar todos los servicios disponibles.
- Usa `-Pn` para evitar el ping inicial (útil si el host filtra ICMP).
- ¡No hagas escaneos en redes que no tienes permiso! ⚠️

# 🌐 Herramientas Web: `curl` y `gobuster`

En retos de tipo Web dentro de un CTF, es común enfrentarse a sitios vulnerables. Herramientas como `curl` y `gobuster` nos permiten **interactuar, inspeccionar y descubrir rutas ocultas**.

---

## 📦 `curl`: Interacción directa con sitios web

### ¿Qué es?

`curl` es una herramienta de línea de comandos que permite **realizar peticiones HTTP** y ver las respuestas. Es ideal para revisar cabeceras, enviar datos, y probar endpoints.

### 🔧 Comandos comunes

| Comando | Descripción |
|--------|-------------|
| `curl http://target.com` | Muestra el contenido HTML |
| `curl -I http://target.com` | Muestra solo las cabeceras (headers) |
| `curl -X POST -d "user=admin" http://target.com/login` | Enviar datos con POST |
| `curl -A "custom-agent" http://target.com` | Cambiar el User-Agent |
| `curl -b "ID=123" http://target.com` | Enviar cookies |

> 🔍 Útil para inspeccionar respuestas de servidores sin usar navegador.

---

## 🕵️‍♂️ `gobuster`: Descubrimiento de directorios y archivos

### ¿Qué es?

`gobuster` es una herramienta de fuerza bruta para descubrir **directorios ocultos, archivos, subdominios, etc.** en un sitio web. Es muy rápida y útil para CTFs donde necesitas encontrar rutas no visibles.

### 🔧 Comandos comunes

| Comando | Descripción |
|--------|-------------|
| `gobuster dir -u http://target.com -w diccionario.txt` | Busca directorios/archivos usando un wordlist |
| `gobuster dns -d target.com -w subdominios.txt` | Fuerza bruta de subdominios |
| `gobuster dir -u http://target.com -x php,html -w diccionario.txt` | Especifica extensiones a buscar |

### 📁 Diccionarios recomendados

- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/`

> 💡 Un descubrimiento con `gobuster` puede abrir puertas a rutas como `/admin`, `/backup`, `/flag`, etc.

---

## 🧠 Consejo

Combina ambas herramientas para inspeccionar y luego explotar servicios:

1. Usa `gobuster` para encontrar `/login`, `/dev`, `/secret`.
2. Usa `curl` para enviar requests personalizados a esas rutas.

---


# 🔐 Cracking de Hashes: ¿Qué es un Hash, qué es un Cifrado y cómo romperlos?

En desafíos CTF, es común encontrarse con hashes o textos cifrados que debemos **revertir, crackear o descifrar** para obtener contraseñas, flags o pistas ocultas.

---

## 🧬 ¿Qué es un Hash?

Un **hash** es una cadena generada a partir de un dato (por ejemplo, una contraseña) usando una función matemática **unidireccional**.

- Siempre produce la misma salida para la misma entrada.
- No se puede “deshacer” (pero se puede adivinar con fuerza bruta).
- Se usa comúnmente para guardar contraseñas de forma segura.

### 🔒 Ejemplo:
Contraseña:     password
Hash MD5:       5f4dcc3b5aa765d61d8327deb882cf99

## 🌐 Herramientas y páginas web útiles
# 🧠 Cómo detectar tipos de cifrado o codificación "a la vista"

En muchos retos de CTF, el primer paso es **reconocer qué tipo de cifrado o codificación** estás viendo. Esta guía te entrega claves visuales, patrones y herramientas para ayudarte a identificarlo.

---

## 🔍 Patrones comunes y qué pueden indicar

| Pista visual                     | Posible tipo                           | Observaciones rápidas                                     |
|----------------------------------|----------------------------------------|-----------------------------------------------------------|
| Solo letras mayúsculas (A-Z)    | **Cifrado César** / **Vigenère**       | Cifrado clásico. Prueba con `dCode` o `CyberChef`.        |
| Termina con `=` o `==`          | **Base64**                             | Longitud múltiplo de 4. Caracteres: A-Z, a-z, 0-9, +, /   |
| Solo números hexadecimales      | **Hex**, **SHA1/SHA256**, etc.         | Hashes y codificaciones binarias                         |
| Empieza con `0x`                | **Hexadecimal**                        | Notación común en programación y binarios                |
| Contiene `%20`, `%3A`, etc.     | **URL encoding**                       | Decodifica con `CyberChef` o `urldecode`                 |
| Empieza con `$1$`, `$6$`, etc.  | **Hashes de Linux**                    | `$1$` = MD5, `$6$` = SHA512                              |
| Comienza con `flag{`, `HTB{`    | **Flag de CTF**                        | Ya descifrado: ¡entrega directa!                         |
| Texto sin sentido o caracteres raros | **XOR / binario / personalizado**   | Usa análisis en CyberChef o Python para probar claves     |





| Herramienta/Sitio                                           | Función                                                |
|-------------------------------------------------------------|---------------------------------------------------------|
| [CyberChef](https://gchq.github.io/CyberChef/)              | Cifrado, codificación, conversión, decodificación       |
| [CrackStation](https://crackstation.net/)                   | Cracking online de hashes comunes                      |
| [Hash-Identifier](https://code.google.com/archive/p/hash-identifier/) | Herramienta para detectar tipos de hash         |
| [MD5decrypt.net](https://md5decrypt.net/)                   | Cracking MD5, SHA1, NTLM, etc.                         |
| [dCode.fr](https://www.dcode.fr/)                           | Decodificadores de cifrados clásicos y modernos        |
| [Hashcat](https://hashcat.net/hashcat/)                     | Herramienta avanzada para cracking con GPU             |



---

## 🪓 John the Ripper (john)

### 🔧 Requisitos

- Guarda el hash en un archivo `hash.txt`
- Usa un wordlist como `rockyou.txt`

### 🧪 Comandos clave

```bash
john --wordlist=rockyou.txt hash.txt                     # Cracking simple con diccionario
john --format=raw-md5 --wordlist=rockyou.txt hash.txt    # Especificar tipo de hash
john --show hash.txt                                     # Mostrar contraseñas crackeadas

##⚡ Hashcat
hashcat -m [modo] -a [ataque] hash.txt wordlist.txt

hashcat -m 0 -a 0 hash.txt rockyou.txt              # Cracking MD5
hashcat -m 100 -a 0 hash.txt rockyou.txt            # Cracking SHA1
hashcat -m 1000 -a 3 hash.txt ?a?a?a?a?a?a          # Ataque de máscara para NTLM (6 chars)

### 🎯 Modos de Hashcat (`-m`)

| Tipo de hash     | Modo  |
|------------------|-------|
| MD5              | `0`   |
| SHA1             | `100` |
| SHA256           | `1400`|
| NTLM (Windows)   | `1000`|
| bcrypt           | `3200`|

---

### ⚔️ Modos de ataque (`-a`)

| Tipo de ataque    | Modo |
|-------------------|------|
| Diccionario       | `0`  |
| Combinación       | `1`  |
| Ataque de máscara | `3`  |


# 🕵️ Análisis Forense y Esteganografía en CTFs

En muchos retos CTF se entregan archivos como imágenes, capturas de red, documentos o binarios. El objetivo es **extraer información oculta** o **recuperar evidencia** que revele una flag.

Este archivo introduce los conceptos básicos de **forense digital** y **esteganografía**, con herramientas y ejemplos comunes.

---

## 🧪 ¿Qué es Forense Digital?

El análisis forense digital consiste en examinar archivos, sistemas o redes para:

- Recuperar datos borrados u ocultos
- Analizar tráfico o memoria
- Detectar metadatos o modificaciones
- Identificar patrones o comportamientos

### 📁 Archivos típicos en retos forenses:

- Imágenes (`.jpg`, `.png`)
- Capturas de red (`.pcap`)
- Archivos comprimidos o dañados
- Memorias (`.raw`)
- Documentos (`.docx`, `.pdf`, `.xlsm`)

---

## 🔧 Herramientas básicas de análisis forense

| Herramienta        | Función principal                          |
|--------------------|--------------------------------------------|
| `strings`          | Extrae texto ASCII de archivos binarios    |
| `binwalk`          | Detecta archivos embebidos o ocultos       |
| `foremost`         | Recupera archivos borrados                 |
| `exiftool`         | Muestra metadatos de imágenes y documentos |
| `Wireshark`        | Análisis de capturas de red `.pcap`        |
| `Volatility`       | Análisis de memoria RAM (`.raw`)           |

---

## 🧩 ¿Qué es Esteganografía?

La esteganografía es el arte de ocultar información dentro de otros archivos sin modificar su apariencia. A menudo se oculta una flag en imágenes, audio o archivos comprimidos.

### 🖼️ Tipos de esteganografía comunes en CTFs:

- **Texto oculto** en los metadatos (EXIF)
- Archivos embebidos en imágenes (`binwalk`)
- Archivos `.zip` con contraseñas ocultas
- Imágenes `.png` con canales LSB alterados (bit menos significativo)
- Mensajes dentro del audio o espectrogramas
- Códigos QR dentro de otras imágenes

---

## 🔧 Herramientas útiles para esteganografía

| Herramienta           | Uso                                     |
|------------------------|------------------------------------------|
| `stegsolve.jar`        | Visualiza canales de color en imágenes   |
| `zsteg` (Linux)        | Detecta LSB ocultos en imágenes `.png`   |
| `steghide`             | Extrae archivos ocultos en `.jpg` / `.wav` |
| `exiftool`             | Lee metadatos EXIF                      |
| `binwalk`              | Detecta y extrae archivos embebidos     |
| `strings`, `xxd`       | Lectura hexadecimal y texto crudo       |

---

## 🧠 Estrategia típica en retos forense/estego

1. **`file`** – identifica el tipo real de archivo
2. **`strings` + `grep flag`** – buscar directamente el texto
3. **`binwalk`** – buscar archivos ocultos dentro de otros
4. **`exiftool`** – ver metadatos
5. **`stegsolve` / `zsteg`** – canales de color en PNG o BMP
6. **`steghide`** – intenta extraer archivos (contraseña a veces es `ctf` o `flag`)
7. **`Wireshark`** – filtra protocolos, busca contraseñas o credenciales

---

## 🎯 Ejemplo simple de análisis

```bash
# Extraer metadatos
exiftool imagen.jpg

# Buscar archivos ocultos
binwalk -e archivo.png

# Extraer cadenas de texto sospechosas
strings archivo.wav | grep flag

# Intentar extraer archivos ocultos
steghide extract -sf imagen.jpg
# 🧨 Pwn para Principiantes — Nivel 1

¿No sabes nada de Pwn? No importa. Aquí aprenderás paso a paso cómo funcionan estos retos.

---

## 🧠 ¿Qué es Pwn?

Pwn es una categoría de retos donde te pasan un **programa (binario)** y tú debes **hacer que haga lo que tú quieras**.

Ejemplo: un programa que te dice "Contraseña incorrecta", pero tú logras que muestre la **flag igual**.

---

## 🔧 Herramientas básicas

No necesitas saber nada raro. Solo usa esto:

| Comando       | ¿Para qué sirve?                      |
|---------------|----------------------------------------|
| `./reto`      | Corre el binario                      |
| `strings reto`| Ver si hay texto útil como `flag{}`   |
| `file reto`   | Ver si es de 32 o 64 bits             |
| `checksec reto`| Ver si tiene protecciones            |

---

## 🎮 Ejemplo real: [gtoBins](https://gtobins.github.io/)

GtoBins es una página que tiene retos de Pwn **súper simples**. Veamos uno.

### ✏️ Paso 1: Descarga y descomprime

```bash
wget https://gtobins.github.io/binaries/bof1.zip
unzip bof1.zip
cd bof1
✏️ Paso 2: Corre el binario
./bof1
Te va a pedir un input. Solo prueba cosas:
AAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 Si se rompe o dice algo raro... ¡vas bien!

# 🛡️ Escalamiento de Privilegios (PrivEsc) — Nivel 1

En muchos retos CTF, logras entrar a una máquina como un usuario común. Pero para capturar la flag final (por ejemplo: `/root/root.txt`), necesitas ser **root**.

El escalamiento de privilegios es el proceso de encontrar una forma de convertirte en root o en un usuario con más permisos.

---

## 🧠 ¿Qué buscar para escalar privilegios?

1. Comandos que puedes ejecutar con `sudo`
2. Archivos que se ejecutan como root
3. Scripts mal configurados
4. Programas con permisos especiales
5. Tareas programadas (cron jobs)

---

## 🔎 Comando más importante: `sudo -l`

```bash
sudo -l
Esto te dice si puedes ejecutar algo como root sin tener la contraseña.

🎯 Ejemplo de salida:
User ctfuser may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/vim
📢 ¡Significa que puedes correr vim como root
🛠 ¿Qué hago si puedo correr un comando como root?
Busca ese comando en GTFOBins para ver si puede usarse para obtener una shell.


🔧 Otras cosas que puedes revisar
|Comando      | archivo	¿Por qué importa?
|-------------|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|                                            |
|sudo         | -l	Ver si puedes ejecutar comandos como root                            |
|find /       | -perm -4000 2>/dev/null	Busca archivos SUID (ejecutan como root)       |
|/etc/crontab |o /etc/cron.*	Revisa tareas programadas que ejecutan scripts           |
|Archivos .sh | con permisos de escritura	Puedes modificarlos si se ejecutan como root |
|linpeas.sh   |	Script que revisa todo automáticamente                                 |
💡 Consejo final
Siempre empieza por lo más simple:

✅ Ejecuta sudo -l
🔍 Busca comandos raros como nano, awk, perl, find
🌐 Revisa en GTFOBins
🛠 Si no sabes qué más revisar → corre linpeas.sh

# 🕵️ OSINT en CTFs — Inteligencia de Fuentes Abiertas

**OSINT** significa "Open Source Intelligence", o inteligencia de fuentes abiertas. En CTFs, esta categoría trata de **encontrar información pública** para resolver un reto.
🎓 OSINT no es hackear: es investigar mejor que nadie.
No necesitas hackear nada, solo **buscar bien**. Lo importante es saber dónde y cómo buscar.

---

## 🔍 ¿Qué puedes buscar en un reto OSINT?

- El correo, número o red social de una persona
- El lugar donde fue tomada una foto
- El autor de un comentario o imagen
- El nombre de un servidor web, empresa o usuario
- Algún dato oculto en redes sociales, sitios web o imágenes

---

## 🛠 Herramientas y sitios útiles

| Herramienta / Sitio                     | Uso principal                                     |
|----------------------------------------|--------------------------------------------------|
| [Google Dorks](https://www.exploit-db.com/google-hacking-database) | Búsquedas avanzadas en Google                    |
| [Exiftool](https://exiftool.org/)      | Ver metadatos de imágenes                        |
| [Social Searcher](https://www.social-searcher.com/) | Buscar publicaciones por nombre o palabra       |
| [Whois](https://who.is/)               | Ver dueño de un dominio web                      |
| [Wayback Machine](https://archive.org/web/) | Ver versiones antiguas de sitios web         |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Buscar un usuario en muchas redes sociales |
| [INTELX.io](https://intelx.io/)        | Buscar correos, leaks, IPs, nombres              |
| [Google Imágenes](https://images.google.com) | Búsqueda inversa de imágenes                    |
| [TinEye](https://tineye.com)           | Otra opción de búsqueda inversa de imágenes      |

---

## 🧠 Técnicas comunes

| Técnica                | Ejemplo práctico                                |
|------------------------|--------------------------------------------------|
| Búsqueda por nombre    | Buscar en Google: `"John Doe" site:linkedin.com`|
| Imagen con metadatos   | Usar `exiftool imagen.jpg`                      |
| Dominio con información| Usar `whois dominio.com`                        |
| Buscar por username    | Usar Sherlock: `python3 sherlock.py juanito`   |
| URL archivada          | Buscar en Wayback Machine                      |
| Google Dorks           | `inurl:admin site:ejemplo.com`                 |

---

## 📌 ¿Cómo abordar un reto OSINT?

1. **Lee con atención** el enunciado. A veces hay pistas ocultas en los nombres o imágenes.
2. Si te dan un nombre, username o correo: **búscalo en redes sociales y foros**.
3. Si te dan una imagen: **usa búsqueda inversa o exiftool**.
4. Si hay un sitio web o dominio: **haz whois, revisa el código fuente, y busca en Wayback Machine**.
5. Si ves números, claves o códigos: **prueba convertirlos o buscarlos en pastebin, leaks o foros.**

---

## ✅ Ejemplo básico de reto OSINT

> Te dan una imagen `selfie.png` y dicen "Encuentra el lugar donde fue tomada".

### 🧪 ¿Qué hacer?

1. Corre:
   ```bash
   exiftool selfie.png
Si hay coordenadas GPS → busca en Google Maps

Si no, súbela a:

Google Imágenes

TinEye

Compara el fondo o edificio con Street View

📢 ¡Boom! Ya encontraste la ciudad. Quizás ahí está la flag 😎 

# ⚙️ SCADA en CTFs — Sistemas Industriales

**SCADA** significa *Supervisory Control and Data Acquisition*. Son sistemas usados en **industrias, plantas eléctricas, agua, fábricas, minería, etc.** para controlar máquinas, sensores y procesos.

En algunos CTFs, hay retos donde debes investigar o atacar entornos simulados de SCADA.

---

## 🧠 ¿Por qué SCADA es importante?

Porque muchos **sistemas críticos del mundo real** (luz, agua, gas, trenes) dependen de ellos. Aprender sobre SCADA en CTFs te prepara para trabajar en **ciberseguridad industrial**.

---

## 🧩 ¿Qué encuentras en un reto SCADA?

- Redes con protocolos industriales
- Interfaces HMI (pantallas de control)
- Archivos de configuración de PLCs (controladores)
- Equipos simulados (Modbus, S7, BACnet)
- Flag oculta en tráfico, comandos o estados de dispositivos

---

## 🔌 Protocolos comunes en retos SCADA

| Protocolo | ¿Para qué sirve?                     |
|-----------|--------------------------------------|
| **Modbus**   | Control de dispositivos (muy usado y simple) |
| **S7**       | Siemens PLCs                       |
| **DNP3**     | Energía eléctrica y automatización |
| **BACnet**   | Control de edificios (clima, luz)  |
| **OPC UA**   | Comunicación de datos industriales |

---

## 🛠 Herramientas para SCADA en CTFs

| Herramienta     | ¿Qué hace?                                        |
|------------------|--------------------------------------------------|
| **Wireshark**    | Analiza tráfico de red industrial (usa filtros como `modbus`) |
| **Scapy**        | Permite crear paquetes para protocolos (incluyendo Modbus)   |
| **modpoll / mbtget** | Herramientas para interactuar con dispositivos Modbus  |
| **Docker + Simuladores** | Algunos CTFs montan entornos virtuales con SCADA    |
| **Python + pyModbus** | Automatización de lectura y escritura en Modbus       |

---

## 📘 Ejemplo básico de tráfico Modbus

En Wireshark puedes filtrar:


Y ver cosas como:

- Lectura de holding registers
- Escritura de coils
- Unidad destino (esclavo)
- Datos transmitidos

A veces la flag está en un "register" o como respuesta a una petición.

---

## 🧪 ¿Cómo empezar con SCADA si no sabes nada?

1. Aprende los conceptos: qué es un PLC, qué hace un HMI, qué es Modbus.
2. Usa [Wireshark](https://www.wireshark.org/) para analizar tráfico capturado (`.pcap`).
3. Mira entornos como:

   - [TryHackMe: ICS & SCADA](https://tryhackme.com/room/icsctf)
   - [Hack The Box: Cyber Apocalypse SCADA rooms](https://www.hackthebox.com/)
   - [CyberRange Chile](https://llaitun.cl)

---

## 🎯 Retos comunes en CTFs SCADA

| Tipo de reto                         | Ejemplo                                                  |
|--------------------------------------|-----------------------------------------------------------|
| Tráfico `.pcap`                      | Encontrar comandos o datos sospechosos                    |
| Archivo de lógica PLC (`.lad`, `.xml`) | Leer lógica de control y encontrar condiciones ocultas     |
| Modbus expuesto en red               | Leer registros y encontrar flag o cambiar estados         |
| Ingeniería inversa de panel HMI      | Analizar una web o app de control industrial              |

---

## 🌐 Recursos para practicar

- [ICS Sandbox (U. of Cambridge)](https://ics.network/)
- [TryHackMe: ICS CTF](https://tryhackme.com/room/icsctf)
- [ControlThings Platform](https://controlthings.io/)
- [ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — técnicas reales de ataque a SCADA
- [GitHub - SCADA Tools](https://github.com/search?q=scada+tools)

---

## 💡 Consejo final

> ⚠️ SCADA no es solo tecnología: es infraestructura crítica.  
> Aprender esto bien te abre puertas al mundo de la **ciberseguridad industrial**, que es muy demandado y fascinante.

🎯 Si ves tráfico con Modbus o un panel con datos de temperatura/presión… estás en un reto SCADA 😎

❓ Preguntas frecuentes (FAQ)
¿Necesito saber programar?
No es obligatorio, pero ayuda mucho. Con conocimientos básicos de Python, Bash o C avanzarás más rápido.
¿Cuánto tiempo tarda en resolverse un reto?
Depende del nivel: desde 10 minutos hasta varias horas. ¡No te frustres si te atoras!
¿Qué hago si me quedo atascado?
Busca pistas, repasa el reto desde otro ángulo, pregunta en comunidades, o consulta writeups (soluciones escritas).

📝 Ejemplo: Reto CTF paso a paso
Reto: Te dan un archivo hash.txt con un hash MD5 y te piden encontrar la contraseña.

Identifica el tipo de hash:
Ejemplo: 5f4dcc3b5aa765d61d8327deb882cf99
Busca el hash en Google:
A veces está público y encuentras la solución al instante.
Crackea con John the Ripper:
bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt
¡Encuentra la flag!
Si el hash corresponde a password, la flag puede ser flag{password} o similar.

❓ Preguntas frecuentes (FAQ)
¿Necesito saber programar?
No es obligatorio, pero ayuda mucho. Con conocimientos básicos de Python, Bash o C avanzarás más rápido.
¿Cuánto tiempo tarda en resolverse un reto?
Depende del nivel: desde 10 minutos hasta varias horas. ¡No te frustres si te atoras!
¿Qué hago si me quedo atascado?
Busca pistas, repasa el reto desde otro ángulo, pregunta en comunidades, o consulta writeups (soluciones escritas).
¿Dónde pido ayuda?
Puedes unirte a Discords, foros, grupos de Telegram o buscar canales de CTF en español.

