# zmq_server.py
import zmq
import time
import argparse
import serial
import os

DEFAULT_ZMQ_HOST = "localhost"
DEFAULT_ZMQ_PORT = 20000

def main():
  parser = argparse.ArgumentParser(description="ZMQ Publisher Server")
  parser.add_argument("-ip", default=DEFAULT_ZMQ_HOST, help="Bind IP")
  parser.add_argument("-port", type=int, default=DEFAULT_ZMQ_PORT, help="Bind Port")
  parser.add_argument("-s", "--serial", help="Serial port for the board", default="/dev/tty.usbmodem101")
  parser.add_argument("-b", "--baudrate", help="Serial badurate", default=115200)
  args = parser.parse_args()

  context = zmq.Context()
  socket = context.socket(zmq.PUB)

  bind_addr = f"tcp://{args.ip}:{args.port}"
  print(f"[SERVER] Binding to {bind_addr}")
  socket.bind(bind_addr)

  ser = serial.Serial(args.serial, args.baudrate)
  ser.write(b"set_bw 8\n")
  ser.write(b"set_sf 8\n")
  ser.write(b"set_pl 8\n")
  ser.write(b"set_freq 920.625\n")
  ser.write(b"set_sw 0x2b\n")
  ser.write(b"set_rx\n")
  try:
    while True:
      msg = ser.readline()
      # msg = msg[4:-8]
      print(f"[SERVER] Sending {msg.hex()}")
      socket.send(msg)
      time.sleep(0.1)
  except KeyboardInterrupt:
    print("\n[SERVER] Interrupted by user, exiting.")
  finally:
    socket.close()
    context.term()
    ser.close()

if __name__ == "__main__":
  main()
