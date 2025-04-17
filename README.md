<br />
<br/>
      	<p width="20px"><b>Se aceptan donaciones para mantener este proyecto</p></b>
	      <a href="https://buymeacoffee.com/investigacq"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=investigacqc&button_colour=FF5F5F&font_colour=ffffff&font_family=Cookie&outline_colour=000000&coffee_colour=FFDD00" /></a><br />
      	<a href="https://www.paypal.com/paypalme/babiloniaetica"><img title="Donations For Projects" height="25" src="https://ionicabizau.github.io/badges/paypal.svg" /></a>
</div>

# 🛡️ ShadowRecon - Bug Bounty & OSINT Automation

ShadowRecon es una herramienta avanzada de Bug Bounty y Reconocimiento Automático diseñada para pentesters e investigadores de seguridad. Su propósito es automatizar la recopilación de información y la detección de vulnerabilidades en dominios objetivos, facilitando el proceso de evaluación de seguridad.

## 🛠️ ¿Para qué sirve?
ShadowRecon permite:

✅ Enumeración de subdominios

✅ Fuzzing de directorios y endpoints

✅ Extracción de endpoints API

✅ Búsqueda de credenciales filtradas en GitHub

✅ Escaneo de buckets S3 expuestos

✅ Detección de vulnerabilidades con Nuclei

✅ Recolección de OSINT desde fuentes públicas

✅ Generación de reportes en JSON y Markdown

⚠️ Solo debe usarse en entornos autorizados.
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
| `--subs`         | Encuentra subdominios del dominio objetivo. |
| `--fuzz`         | Realiza fuzzing de directorios y archivos sensibles. |
| `--api`          | Extrae endpoints de APIs públicas o internas. |
| `--nuclei`       | Escanea vulnerabilidades con plantillas de Nuclei. |
| `--osint`        | Recolecta información OSINT desde múltiples fuentes. |
| `--s3`           | Busca buckets de Amazon S3 expuestos. |
| `--github`       | Escanea credenciales filtradas en GitHub. |
| `--report`       | Genera reportes en formatos JSON y Markdown. |
| `-o, --output`   | Especifica el directorio donde se guardarán los reportes. |
| `-t, --threads`  | Define el número de hilos para mejorar la velocidad de escaneo. |
| `-v, --verbose`  | Muestra información detallada del proceso de escaneo. |
| `-h, --help`     | Muestra la ayuda con todas las opciones disponibles. |

## LICENCIA
Este proyecto está licenciado bajo la licencia **MIT**. Consulte el archivo `LICENCIA` para más detalles.

---

## Author
Created with ❤️ by [@Zuk4r1](https://github.com/Zuk4r1).

# ¡Feliz hackeo! 🎯
