import platform
import threading
import time
import os
import queue

DEFAULT_TIMEOUT_JOIN = 1
DEFAULT_FILENAME = "ffifo"

if platform.system() == "Windows":
    try:
        import win32pipe, win32file, pywintypes
    except ImportError:
        print(
            "\x1b[33;1mError: win32pipe, win32file, pywintypes modules not found. Please install pywin32 package.\x1b[0m"
        )
        exit(1)

class CoreFifo:
    def __init__(self, recv_queue=None):
        self.fifo_running = False
        self.recv_queue = recv_queue if recv_queue else queue.Queue()
        self.ff_pipeline = None
        self.fifo_path = None  # Se definirá en la subclase
        self.recv_worker = None

    def create(self):
        try:
            os.mkfifo(self.fifo_path)
        except OSError as e:
            print(f"Error creating FIFO: {e}")

    def open(self):
        if not os.path.exists(self.fifo_path):
            self.create()
        try:
            self.ff_pipeline = open(self.fifo_path, "ab")
        except OSError as e:
            print(f"Error opening FIFO: {e}")

    def stop_core(self):
        print("Stop core")
        self.fifo_running = False

        if self.recv_worker and self.recv_worker.is_alive():
            self.recv_queue.put(None)  # Enviar sentinel para detener `run_fifo`
            self.recv_worker.join(timeout=DEFAULT_TIMEOUT_JOIN)

        if self.ff_pipeline:
            self.ff_pipeline.close()
        print("Cleaning fifo")
        try:
            os.remove(self.fifo_path)
        except FileNotFoundError:
            pass  # Si ya fue eliminado, no hacer nada
        


class Fifo(CoreFifo):
    def __init__(self, fifo_filename=DEFAULT_FILENAME, recv_queue=None):
        super().__init__(recv_queue)
        self.fifo_path = os.path.join("/tmp", fifo_filename)

    def run_fifo(self):
        """Bucle principal que lee datos de la cola y los escribe en la FIFO."""
        self.fifo_running = True
        self.open()  # Abrir la FIFO

        while self.fifo_running:
            try:
                data = self.recv_queue.get(timeout=0.1)  # Evita bloqueo indefinido
                if data is None:
                    break  # Señal de detener el hilo

                self.ff_pipeline.write(data)
                self.ff_pipeline.flush()
            except queue.Empty:
                continue  # Si no hay datos, seguir esperando
            except BrokenPipeError:
                break  # La FIFO fue cerrada
            except Exception as e:
                print(f"Error in run_fifo: {e}")
                break

    def stop(self):
        print("Stop Fifo")
        self.stop_core()

    def main(self):
        """Inicia el hilo de escritura en la FIFO."""
        self.recv_worker = threading.Thread(target=self.run_fifo)
        self.recv_worker.start()
