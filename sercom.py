import time
import queue
import simplecom
from main import Decrypter



if __name__ == "__main__":
  dec = Decrypter()
  catsnifQueue = queue.Queue()
  
  catsnfMonitor = simplecom.SerialMonitor("/dev/tty.usbmodem2123201", 921600, catsnifQueue)

  try:
    catsnfMonitor.main()
    while True:
      if not catsnifQueue.empty():
        data = catsnifQueue.get()
        # print(f"Sniffer: {data}")
        if b"Bytes:" in data:
          bytes_data = data.split(b":")[1]
          dec.decrypt(bytes_data.replace(b"\n", b"").hex())
        
      time.sleep(0.1)
  except KeyboardInterrupt:
    catsnfMonitor.close()
