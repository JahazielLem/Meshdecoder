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

# This script only shows how to use has publisher for another device to communicate with the transporter

import zmq
import time
import argparse
import serial

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
      print(f"[SERVER] Sending {msg}")
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
