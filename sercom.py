import time
import sys
import queue
from main import Decrypter
from modules.fifo import Fifo
from modules.pcap import get_global_header, Pcap
from modules.decoder import Decrypter
from modules.simplecom import SerialMonitor


def dissect_catsniffer_payload(data):
  start_f = b"@S"
  end_f = b"@E"
  bytestream = data.find(start_f)
  sof_index = 0

  eof_index = bytestream.find((end_f + start_f), sof_index)
  if eof_index == -1:
    return None

  bytestream = start_f + bytestream[sof_index : eof_index + 2]
  return bytestream

if __name__ == "__main__":
  running = False
  dec = Decrypter()
  catsnifQueue = queue.Queue()
  fifoQueue = queue.Queue()
  
  catsnfMonitor = SerialMonitor("/dev/tty.usbmodem2123401", 921600, catsnifQueue)
  fifoWorker = Fifo("flora", fifoQueue)
  headerPcap = False

  try:
    catsnfMonitor.main()
    catsnfMonitor.serial_device.transmit("set_sf 8\n")
    catsnfMonitor.serial_device.transmit("set_rx\n")
    fifoWorker.main()
    running = True
    while running:
      if not catsnifQueue.empty():
        data = catsnifQueue.get()
        catsnifQueue.task_done()
        print(f"Sniffer: {data}")
        if not headerPcap:
          headerPcap = True
          fifoQueue.put(get_global_header(148))
        fifoQueue.put(Pcap(data, time.time()).get_pcap())
        
      time.sleep(0.1)
    
    catsnfMonitor.close()
    fifoWorker.stop()
  except KeyboardInterrupt:
    running = False
    

