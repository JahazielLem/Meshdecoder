import time
import queue
import simplecom
from main import Decrypter
from modules.fifo import Fifo
from modules.pcap import get_global_header, Pcap


if __name__ == "__main__":
  dec = Decrypter()
  catsnifQueue = queue.Queue()
  fifoQueue = queue.Queue()
  
  catsnfMonitor = simplecom.SerialMonitor("/dev/tty.usbmodem2123201", 921600, catsnifQueue)
  fifoWorker = Fifo("flora", fifoQueue)
  headerPcap = False

  try:
    catsnfMonitor.main()
    catsnfMonitor.serial_device.transmit("set_sf 8\n")
    catsnfMonitor.serial_device.transmit("set_rx\n")
    fifoWorker.main()
    while True:
      if not catsnifQueue.empty():
        data = catsnifQueue.get()
        if b"LoRa" in data:
          continue
        if b"[SX1262]" in data:
          continue
        print(f"Sniffer: {data}")
        if not headerPcap:
          headerPcap = True
          fifoQueue.put(get_global_header(148))
        fifoQueue.put(Pcap(data, time.time()).get_pcap())
        # if b"Bytes:" in data:
        #   bytes_data = data.split(b":")[1]
        #   dec.decrypt(bytes_data.replace(b"\n", b"").hex())
        
      time.sleep(0.1)
  except KeyboardInterrupt:
    # fifoWorker.close()
    catsnfMonitor.close()
