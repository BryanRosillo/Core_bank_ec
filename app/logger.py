import os
import datetime
from flask import request

# Ruta donde se almacenarán los logs
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")

# Asegurarse de que la carpeta de logs exista
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
    print(f"Carpeta {LOG_DIR} creada correctamente.")


def mask_ip(ip):
    """
    Enmascara parcialmente la IP (solo muestra los primeros 3 octetos).
    """
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.XXX.XXX"

def mask_username(username):
    """
    Enmascara el nombre de usuario, si es necesario.
    """
    return "Anonymous" if not username else username


def mask_sensitive_data(log_entry):
    """
    Enmascara información sensible en el log, como números de cuenta, transacciones, etc.
    """
    log_entry = log_entry.replace("account_number", "****")  # Sustituye números de cuenta
    log_entry = log_entry.replace("password", "****")  # Sustituye contraseñas
    return log_entry


def write_log(log_type, username, action, status_code):
    """
    Registra una entrada en el archivo de logs con información enmascarada.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    # Enmascarar IP y nombre de usuario
    ip_address = mask_ip(request.remote_addr if request else "Unknown")
    username = mask_username(username)

    log_entry = f"{timestamp} | {log_type} | {ip_address} | {username} | {action} | {status_code}\n"

    # Enmascarar información sensible si es necesario
    log_entry = mask_sensitive_data(log_entry)

    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)
