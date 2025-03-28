import zmq
import queue
import time
import threading

from modules.pcap import Pcap
from modules.fifo import FifoLinux

context = zmq.Context()

class ZMQClient:
  def __init__(self, host="localhost", port=20000, rx_queue=queue.Queue()):
    self.server = f"tcp://{host}:{port}"
    self.socket = None
    self.rx_queue = rx_queue
    self.running = False

  def connect(self):
    self.socket = context.socket(zmq.SUB)
    try:
      print(f"Connect to: {self.server}")
      self.socket.connect(self.server)
      self.socket.setsockopt(zmq.SUBSCRIBE, b'')
      self.running = True
    except Exception as e:
      print(e)
      raise e
  
  def recv(self):
    while self.running:
      if self.socket.poll(10):
        recv = self.socket.recv()
        if recv:
          self.rx_queue.put(recv)
      else:
        time.sleep(0.1)
  
  def disconnect(self):
    self.running = False
    self.socket.close()


if __name__ == "__main__":
  fifom = FifoLinux("fmeshtastic")
  mainQueue = queue.Queue()
  ip = "192.168.0.183"
  
  shortSlow = ZMQClient(ip, 20001, mainQueue)
  mediumSlow = ZMQClient(ip, 20003, mainQueue)
  
  shortSlow.connect()
  mediumSlow.connect()
  
  th_pipeline = threading.Thread(target=fifom.run)
  th_shortSlow  = threading.Thread(target=shortSlow.recv)
  th_mediumSlow = threading.Thread(target=mediumSlow.recv)
    
  th_pipeline.start()
  th_shortSlow.start()
  th_mediumSlow.start()

  try:
    while True:
      if not mainQueue.empty():
        data = mainQueue.get(timeout=1)
        if data:
          print(f"Recv -> {data}")
          pcap_data = Pcap(data, timestamp_seconds=time.time())
          fifom.add_data(pcap_data.get_pcap())
      time.sleep(1)
  except KeyboardInterrupt:
    shortSlow.disconnect()
    mediumSlow.disconnect()
    fifom.stop_worker()
    th_shortSlow.join(timeout=1)
    th_mediumSlow.join(timeout=1)
    th_pipeline.join(timeout=1)

