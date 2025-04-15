import platform
import threading
import queue
import time
import os

DEFAULT_TIMEOUT_JOIN = 1
from .utils import LOG_WARNING, LOG_SUCCESS

if platform.system() == "Windows":
  try:
    DEFAULT_PIPEPATH = f"\\\\.\\pipe\\ftransporter"
    import win32pipe, win32file, pywintypes
  except ImportError:
    print(
        "\x1b[33;1mError: win32pipe, win32file, pywintypes modules not found. Please install pywin32 package.\x1b[0m"
    )
else:
  DEFAULT_PIPEPATH = "/tmp/ftransporter"

class PipelineExcetion(Exception):
  pass


class Pipeline:
  def __init__(self):
    self.pipeline = None
    self.worker_pipeline = threading.Thread()
    self.running = False

class PipeUnix(Pipeline):
  f"""Create a Pipeline in /tmp/{DEFAULT_PIPEPATH} by default"""
  def __init__(self, pipe_path=DEFAULT_PIPEPATH, data_queue=queue.Queue()):
    super().__init__()
    self.pipe_path = pipe_path
    self.data_queue = data_queue
    self.pipeline = None
    self.worker_pipeline = threading.Thread()
    self.running = False
  
  def create(self):
    try:
      if not os.path.exists(self.pipe_path):
        os.mkfifo(self.pipe_path)
      else:
        self.remove()
    except OSError as e:
      raise PipelineExcetion(e)
  
  def open(self):
    if not os.path.exists(self.pipe_path):
      self.create()
    
    try:
      LOG_WARNING("[FIFO] Wainting for connection with the pipeline")
      self.pipeline = open(self.pipe_path, "ab")
      LOG_SUCCESS("[FIFO] Connected")
    except OSError as e:
      raise PipelineExcetion(e)
  
  def remove(self):
    try:
      os.remove(self.pipe_path)
    except FileNotFoundError:
      pass
    except OSError as e:
      raise PipelineExcetion(e)
  
  def __worker(self):
    while self.running:
      try:
        if not self.pipeline:
          pass
        if not self.data_queue.empty():
          data = self.data_queue.get()
          if data:
            self.pipeline.write(data)
            self.pipeline.flush()
          self.data_queue.task_done()
        time.sleep(0.1)
      except Exception as e:
        raise PipelineExcetion(e)
  
  def pipeline_stop(self):
    self.running = False
    if self.worker_pipeline and self.worker_pipeline.is_alive():
      self.worker_pipeline.join(timeout=DEFAULT_TIMEOUT_JOIN)
    self.remove()
  
  def pipeline_run(self):
    self.create()
    self.open()
    self.running = True
    self.worker_pipeline = threading.Thread(target=self.__worker, daemon=True)
    self.worker_pipeline.start()

class PipeWindows(Pipeline):
  def __init__(self, pipe_path=DEFAULT_PIPEPATH, data_queue=queue.Queue()):
    super().__init__()
    self.pipe_path = pipe_path
    self.data_queue = data_queue

  def create(self):
    try:
      if not os.path.exists(self.pipe_path):
        self.pipeline = win32pipe.CreateNamedPipe(
            self.fifo_path,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE
            | win32pipe.PIPE_READMODE_MESSAGE
            | win32pipe.PIPE_WAIT,
            1,
            65536,
            65536,
            0,
            None,
        )
      else:
        raise PipelineExcetion(f"Already exist a file: {self.pipe_path}")
    except pywintypes.error as e:
      raise PipelineExcetion(e)

  def open(self):
    if not os.path.exists(self.pipe_path):
      self.create()
    try:
      win32pipe.ConnectNamedPipe(self.pipeline, None)
    except OSError as e:
      raise PipelineExcetion(e)
  
  def remove(self):
    try:
      os.remove(self.pipe_path)
    except FileNotFoundError:
      pass
    except OSError as e:
      raise PipelineExcetion(e)
  
  def __worker(self):
    while self.running:
      try:
        if not self.pipeline:
          pass
        if not self.data_queue.empty():
          data = self.data_queue.get()
          if data:
            win32file.WriteFile(self.pipeline, data)
            win32file.FlushFileBuffers(self.pipeline)
          self.data_queue.task_done()
        time.sleep(0.1)
      except pywintypes.error as e:
        raise PipelineExcetion(e)
  
  def pipeline_stop(self):
    self.running = False
    if self.worker_pipeline and self.worker_pipeline.is_alive():
      self.worker_pipeline.join(timeout=DEFAULT_TIMEOUT_JOIN)
    self.remove()
  
  def pipeline_run(self):
    self.create()
    self.open()
    self.worker_pipeline = threading.Thread(target=self.__worker, daemon=True)
    self.worker_pipeline.start()