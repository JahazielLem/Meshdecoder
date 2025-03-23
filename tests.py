import os
import pty
import serial
import time

def create_virtual_serial():
    master, slave = pty.openpty()  # Crea el pseudoterminal
    slave_name = os.ttyname(slave)  # Obtiene el nombre del dispositivo

    print(f"📡 Dispositivo virtual creado: {slave_name}")
    print(f"🔌 Conéctate usando: screen {slave_name} 115200")

    try:
        while True:
            data = os.read(master, 1024)  # Lee datos si alguien se conecta
            print(f"📥 Recibido: {data.decode(errors='ignore')}")
            os.write(master, b"Respuesta desde el serial virtual\n")
    except KeyboardInterrupt:
        print("\n🔴 Cerrando el puerto virtual.")
        os.close(master)
        os.close(slave)

if __name__ == "__main__":
    create_virtual_serial()
