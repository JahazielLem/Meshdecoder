import platform
import threading
import time
import os
import logging
import sys
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

class CoreFifo(threading.Thread):
    def __init__(self, recv_queue=queue.Queue()):
        threading.Thread.__init__(self)

        self.ff_pipeline = None
        self.fifo_running = False
        self.fifo_need_header = True
        self.fifo_data = []
        self.fifo_packet = None
        self.last_packet = None
        self.linktype = 1
        self.fifo_data_lock = threading.Lock()
        self.daemon = True
        self.recv_queue = recv_queue
        self.recv_worker = None

    def set_linktype(self, linktype: int):
        self.linktype = linktype
    
    def create(self):
        try:
            os.mkfifo(self.fifo_path)
        except OSError as e:
            print(e)
    
    def open(self):
        if os.path.exists(self.fifo_path) == False:
            self.create()
        try:
            self.ff_pipeline = open(self.fifo_path, "ab")
        except OSError as e:
            print(e)
    
    def close(self):
        print("closing")
        self.fifo_running = False
        while not self.recv_queue.empty():
           self.recv_queue.get()
           self.recv_queue.task_done()
        if self.recv_worker and self.recv_worker.is_alive():
            self.recv_worker.join(timeout=DEFAULT_TIMEOUT_JOIN)
        if self.ff_pipeline:
            self.ff_pipeline.close()
        try:
            os.remove(self.fifo_path)
        except FileNotFoundError as e:
            print(f"Error: {e}")
        self.join(timeout=DEFAULT_TIMEOUT_JOIN)
    
    def set_fifo_filename(self, fifo_filname: str):
        self.fifo_filname = fifo_filname


class Fifo(CoreFifo):
  def __init__(self, fifo_filname: str = DEFAULT_FILENAME, recv_queue=None):
    if recv_queue is None:
       recv_queue = queue.Queue()
    super().__init__(recv_queue)
    self.fifo_filname = fifo_filname
    self.ff_pipeline = None
    self.fifo_path = os.path.join("/tmp", self.fifo_filname)

  def run_fifo(self):
    self.fifo_running = True
    print("Start")
    self.start()
    print("Next")
    if self.ff_pipeline is None:
        self.open()
    while self.fifo_running:
      try:
        print('recv')
        data = self.recv_queue.get()
        if data:
          print(f"fifo: {data}")
          self.ff_pipeline.write(data)
          self.ff_pipeline.flush()
        else:
          time.sleep(0.01)
      except BrokenPipeError as e:
        pass
      except Exception as e:
        print(e)
        break
    
  def main(self):
    self.recv_worker = threading.Thread(target=self.run_fifo)
    self.recv_worker.start()

    
