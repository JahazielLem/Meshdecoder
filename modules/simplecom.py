import argparse
import serial
import time
import threading
import queue
from datetime import datetime
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

DEFAULT_BAUDRATE = 115200
DEFAULT_CRLF = "\r\n"

class SerialError(Exception):
  pass

class SerialPort:
  def __init__(self, port="/dev/ttyUSB0", baudrate=DEFAULT_BAUDRATE):
    if port is None:
      raise SerialError("Serial port is None")
    if baudrate is None:
      baudrate = DEFAULT_BAUDRATE
    self.serial_device = serial.Serial(port=port, baudrate=baudrate)
    self.serial_line_control = DEFAULT_CRLF
    self.serial_alive = False
  
  def set_serial_port(self, port):
    self.serial_device.port = port
  
  def set_baudrate(self, baudrate):
    if baudrate not in serial.Serial.BAUDRATES:
      raise ValueError("Invalid baudrate")
    self.serial_device.baudrate = baudrate
  
  def get_port(self):
    return self.serial_device.port
  
  def is_connected(self):
    return self.serial_device.is_open

  def resetBuffer(self):
    self.serial_device.reset_input_buffer()
    self.serial_device.reset_output_buffer()

  def validate_connectio(self):
    try:
      self.serial_device.open()
      self.close()
      return True
    except (serial.SerialException, FileNotFoundError):
      return False
  
  def open(self):
    try:
      if self.is_connected():
        self.close()
      
      self.serial_device.open()

      self.resetBuffer()
      self.serial_alive = True
    except serial.SerialException as e:
      raise SerialError(e)
  
  def close(self):
    try:
      self.serial_device.close()
      self.serial_alive = False
    except serial.SerialException as e:
      raise SerialError(e)
  
  def recv(self):
    try:
      if self.serial_device.in_waiting > 0:
        bytestream = self.serial_device.read_until(b"\n")
        return bytestream
    except (serial.SerialException, UnicodeDecodeError):
      self.serial_alive = False
      return None
  
  def transmit(self, data):
    try:
      message = f"{data}{self.serial_line_control}"
      self.serial_device.write(message.encode())
    except serial.SerialException as e:
      print(f"Error: {e}")
  
  def reconnect(self, max_attempts=5):
    attempts = 0
    while not self.serial_alive and attempts < max_attempts:
      time.sleep(3)
      try:
        print("Reconnecting")
        self.open()
        return
      except SerialError:
        attempts += 1
    if not self.serial_alive:
      print("No connected")
    else:
      print("Connected")

class SerialMonitor:
  def __init__(self, port=None, baudrate=None, rx_queue=queue.Queue(), prompt=True):
    self.prompt_session = PromptSession()
    self.serial_device = SerialPort(port, baudrate)
    self.running_app = True
    self.show_prompt = prompt
    self.cmd_char = ""

    self.prompt_worker = None
    self.serial_worker = None
    self.queu_worker = None
    self.rx_queue = rx_queue
  
  def __prompt_worker(self):
    with patch_stdout():
      while self.running_app:
        try:
          text = self.prompt_session.prompt(self.cmd_char)
          self.serial_device.transmit(text)
        except (KeyboardInterrupt, EOFError):
          self.running_app = False
          break
  
  def __rx_serial_worker(self):
    while self.running_app:
      try:
        data = self.serial_device.recv()
        if data:
          self.rx_queue.put(data)
      except Exception as e:
        print(e)
        self.serial_device.close()
        time.sleep(1)
        self.serial_device.reconnect()
    
  def show_data(self):
    while self.running_app:
      try:
        if not self.rx_queue.empty():
          data = self.rx_queue.get()
          time_now = datetime.now().strftime("%H:%M:%S")
          print(f"{data}")
      except Exception as e:
        print("Error Queue: ", e)
    
  def rx_worker(self):
    self.serial_worker = threading.Thread(target=self.__rx_serial_worker)
    self.serial_worker.start()

  def prompt(self):
    self.prompt_worker = threading.Thread(target=self.__prompt_worker)
    self.prompt_worker.start()
  
  def queue_worker(self):
    self.queu_worker = threading.Thread(target=self.show_data)
    self.queu_worker.start()

  def close(self):
    self.running_app = False
    time.sleep(0.5)
    if self.show_prompt:
      if self.prompt_worker and self.prompt_worker.is_alive():
        self.prompt_worker.join(timeout=2)
    if self.serial_worker and self.serial_worker.is_alive():
      self.serial_worker.join(timeout=2)
    if self.queu_worker and self.queu_worker.is_alive():
      self.queu_worker.join(timeout=2)
    print("Closing serial")
    self.serial_device.close()
      
  def main(self):
    self.serial_device.open()
    self.cmd_char = f"[{self.serial_device.get_port()}] ?>"
    self.rx_worker()
    if self.show_prompt:
      self.prompt()
      

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("port", help="Serial port")
  parser.add_argument("-b", "--baudrate", help="Baudrate", type=int, default=DEFAULT_BAUDRATE)
  args = parser.parse_args()
  
  serial_monitor = SerialMonitor(args.port, args.baudrate)
  try:
    serial_monitor.main()
    serial_monitor.queue_worker()
    while serial_monitor.running_app:
      time.sleep(1)
  except KeyboardInterrupt:
    serial_monitor.close()

if __name__ == "__main__":
  main()
