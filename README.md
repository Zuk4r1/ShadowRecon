# 🛡️ ShadowRecon - Bug Bounty & OSINT Automation

ShadowRecon es una herramienta de reconocimiento automático y escaneo de vulnerabilidades, orientada a profesionales de seguridad, investigadores y cazadores de bugs. Automatiza el proceso de recolección de información, análisis de superficie de ataque y explotación básica, en dominios y sistemas expuestos.

---

## 🧰 Funcionalidades principales

✅ Enumeración de subdominios  
✅ Fuzzing de directorios y parámetros GET  
✅ Fingerprinting de tecnologías y frameworks  
✅ Extracción de endpoints API  
✅ Recolección OSINT de múltiples fuentes  
✅ Escaneo de vulnerabilidades con Nuclei  
✅ Escaneo agresivo de puertos y cabeceras HTTP  
✅ Búsqueda de credenciales filtradas en GitHub  
✅ Detección de buckets S3 expuestos  
✅ Fuerza bruta de login con diccionarios  
✅ Test de SSRF, CRLF, Host Header Injection  
✅ Subida de archivos maliciosos para testeo  
✅ Detección de redirecciones abiertas, backups y más  
✅ Ejecución multihilo y modo paralelo/agresivo  
✅ Soporte para proxies y rotación de User-Agent  
✅ Reportes en JSON, Markdown y salida personalizada  
✅ Logging avanzado y manejo robusto de errores  
✅ Banner de advertencia legal en ejecución

⚠️ **Uso exclusivo para entornos autorizados y pruebas éticas.**

---

# 🚀 Instalación

## 1️⃣ Clonar el repositorio
```
git clone https://github.com/tuusuario/shadowrecon.git
cd shadowrecon
```

## 2️⃣ Instalar dependencias
```
pip install -r requirements.txt
```

## 3️⃣ Instalar herramientas externas (opcional, pero recomendado)
```
apt install ffuf
pip install theHarvester shodan censys
curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
| grep browser_download_url | grep linux_amd64.zip \
| cut -d '"' -f 4 | wget -qi - && unzip nuclei-linux-*.zip && chmod +x nuclei && sudo mv nuclei /usr/local/bin/
```

## ⚙️ Uso rápido

```
python shadowrecon.py -d target.com --subs --fuzz --api --nuclei --osint --report
```

## 👹 Modo agresivo/intrusivo
```
python shadowrecon.py -d target.com --aggressive --threads 100 --proxy http://127.0.0.1:8080 -v
```

## 🕵️ Escaneo de un dominio completo con verbose activado:
```
python shadowrecon.py -d target.com --subs --nuclei --osint --report -v
```

## 🚀 Fuzzing con 50 hilos y salida en un directorio personalizado:
```
python shadowrecon.py -u https://target.com --fuzz -t 50 -o results/
```

## 🔧 Banderas Disponibles

| Flag              | Descripción |
|------------------|--------------------------------------|
| `-d, --domain`   | Especifica el dominio objetivo. |
| `-u, --url`	   | URL completa a escanear. |
| `--subs`         | Encuentra subdominios del dominio objetivo. |
| `--fuzz`         | Realiza fuzzing de directorios y archivos sensibles. |
| `--api`          | Extrae endpoints de APIs públicas o internas. |
| `--nuclei`       | Escanea vulnerabilidades con plantillas de Nuclei. |
| `--osint`        | Recolecta información OSINT desde múltiples fuentes. |
| `--s3`           | Busca buckets de Amazon S3 expuestos. |
| `--github`       | Escanea credenciales filtradas en GitHub. |
| `--headers`	   | Escanea cabeceras de seguridad en respuestas HTTP. |
| `--ports`	   | Realiza escaneo agresivo de puertos para identificar servicios expuestos. |
| `--tech`	   | Detecta tecnologías y frameworks utilizados por el objetivo. |
| `--ssrf`	   | Ejecuta pruebas automáticas de SSRF (Server-Side Request Forgery). |
| `--crlf`	   | Ejecuta pruebas automáticas de CRLF Injection. |
| `--host`	   | Ejecuta pruebas de Host Header Injection. |
| `--upload`	   | Intenta subir archivos maliciosos para detectar fallos en validaciones. |
| `--brute`	   | Realiza fuerza bruta en formularios de login para detectar credenciales débiles. |
| `--aggressive`   | Ejecuta todos los módulos de forma paralela con técnicas intrusivas. |
| `--user-agent`   | Define un User-Agent personalizado. |
| `--proxy`	   | Usa un proxy HTTP o SOCKS (por ejemplo, Burp Suite o Tor). |
| `--report`       | Genera reportes en formatos JSON y Markdown. |
| `-o, --output`   | Especifica el directorio donde se guardarán los reportes. |
| `-t, --threads`  | Define el número de hilos para mejorar la velocidad de escaneo. |
| `--timeout`	   | Establece un tiempo máximo de espera para cada módulo. |
| `-v, --verbose`  | Muestra información detallada del proceso de escaneo. |
| `-h, --help`     | Muestra la ayuda con todas las opciones disponibles. |

## ⚖️ LICENCIA
Este proyecto está licenciado bajo la licencia **MIT**. Consulte el archivo [`LICENCIA`](https://github.com/Zuk4r1/ShadowRecon/blob/main/LICENSE) para más detalles.

## 👨‍💻 Autor

Created with ❤️ by [@Zuk4r1](https://github.com/Zuk4r1). – defensor del hacking ético y la investigación digital.

## ⚠️ Aviso legal

Esta herramienta está destinada exclusivamente a pruebas de seguridad con fines educativos y en entornos controlados con autorización expresa. El uso indebido es responsabilidad exclusiva del usuario.

## ☕ Apoya mis proyectos
Si te resultan útiles mis herramientas, considera dar una ⭐ en GitHub o invitarme un café. ¡Gracias!

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/investigacq)  [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/yordansuarezrojas)


# ¡Feliz hackeo! 🎯
