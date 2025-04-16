# Written by Jahaziel 2025
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# This script works as transporter to connect with wireshark

import zmq
import time
import queue
import threading
import argparse
import platform
from modules.fifo import PipeUnix, PipeWindows, DEFAULT_PIPEPATH
from modules.pcap import get_global_header, Pcap, LINKTYPE_USER_DLT
from modules.utils import LOG_SUCCESS, LOG_WARNING, LOG_ERROR, LOG_INFO, hexdump

DEFAULT_ZMQ_HOST = "localhost"
DEFAULT_ZMQ_PORT = 20000

class ZMQClient:
  def __init__(self, host=DEFAULT_ZMQ_HOST, port=DEFAULT_ZMQ_PORT, recv_queue=queue.Queue()):
    self.context = zmq.Context()
    self.server = f"tcp://{host}:{port}"
    self.recv_queue = recv_queue
    self.socket = None
    self.running = False
    self.worker_recv = threading.Thread()
  
  def connect(self):
    self.socket = self.context.socket(zmq.SUB)
    try:
      LOG_SUCCESS(f"[*] Connecting to {self.server}")
      self.socket.connect(self.server)
      self.socket.setsockopt(zmq.SUBSCRIBE, b'')
      self.running = True
    except Exception as e:
      raise e
  
  def recv(self):
    while self.running:
      try:
        if self.socket.poll(10) != 0:
          data = self.socket.recv()
          if data:
            print("Packet:")
            print(hexdump(data=data))
            self.recv_queue.put(data)
        time.sleep(0.1)
      except Exception as e:
        raise e
  
  def start(self):
    self.running = True
    self.worker_recv = threading.Thread(target=self.recv, daemon=True)
    self.worker_recv.start()
  
  def dissconnect(self):
    self.running = False
    if self.worker_recv and self.worker_recv.is_alive():
      self.worker_recv.join()
    self.socket.close()

class Transporter:
  def __init__(self, host=DEFAULT_ZMQ_HOST, port=DEFAULT_ZMQ_PORT, pipeline=DEFAULT_PIPEPATH, linktype=LINKTYPE_USER_DLT):
    self.recv_queue = queue.Queue()
    self.transport_queue = queue.Queue()
    self.client = ZMQClient(host, port, self.recv_queue)
    self.pipeline = PipeWindows(pipe_path=pipeline, data_queue=self.transport_queue) if platform.system() == "Windows" else PipeUnix(pipe_path=pipeline, data_queue=self.transport_queue)
    self.running = False
    self.linktype = linktype
    self.pcap_global_header = False
  
  def start(self):
    self.running = True
    self.pipeline.pipeline_run()
    self.client.connect()
    self.client.start()
    while self.running:
      try:
        if not self.recv_queue.empty():
          data = self.recv_queue.get()
          if data:
            if not self.pcap_global_header:
              self.transport_queue.put(get_global_header(self.linktype))
              self.pcap_global_header = True
            pcap = Pcap(data, time.time())
            self.transport_queue.put(pcap.bytes())
          self.recv_queue.task_done()
        time.sleep(0.1)
      except KeyboardInterrupt:
        self.running = False
      except Exception as e:
        raise e
    self.pipeline.pipeline_stop()
    self.client.dissconnect()


if __name__ == "__main__":
  parser = argparse.ArgumentParser(prog="transporter", description="ZMQ transporter to wireshark", epilog="JahazielLem")
  zmq_publisher = parser.add_argument_group("ZMQ Publisher", "ZMQ publisher server")
  zmq_publisher.add_argument("-ip", help="Server IP", default=DEFAULT_ZMQ_HOST)
  zmq_publisher.add_argument("-port", help="Server Port", default=DEFAULT_ZMQ_PORT)
  zmq_publisher.add_argument("-pipe", help="Pipeline path for wireshark", default=DEFAULT_PIPEPATH)
  zmq_publisher.add_argument("-l", "--linklayer", help="Linklayer for the dissector", default=LINKTYPE_USER_DLT)
  args = parser.parse_args()
  LOG_WARNING("This script is still under development, use by you own risk")
  LOG_INFO("Tested on:")
  LOG_SUCCESS("[*] MacOS -> Happy path works well :P")
  LOG_WARNING("[x] Linux -> Not testing yet")
  LOG_ERROR("[x] Windows -> Still in development")
  transport = Transporter(args.ip, args.port, args.pipe, args.linklayer)
  transport.start()
