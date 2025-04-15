
> [!NOTE]
> 🚧 Project in Development 🚧
> This project is currently under development and may fail.

# Meshdecoder
Scripts for decoding packets of meshtastic nodes.


# Install Dissector
- Download the latest version of the dissector for your operating system from the [MeshtasticDissector GitHub Releases](https://github.com/JahazielLem/MeshtasticDissector/releases) page.
- Open Wireshark.
- For Windows/Linux users:
  1. Go to Help → About Wireshark.
  2. Navigate to the Folders tab and double-click the path for Personal Plugins.
  3. A file explorer window will open. Copy and paste the .dll file (Windows) or .so file (Linux) into that folder.
- For macOS users:
  1. Go to Wireshark → About Wireshark.
  2. Navigate to the Folders tab and double-click the path for Personal Plugins.
  3. A Finder window will open. Copy and paste the .so file into that folder.

> [!IMPORTANT]
> 🚧 Project in Development 🚧
> This project is currently under development and may fail. The dissector is not tested on all the operative systems and some packets may show as `Dissector Error`. Please be patient.


# Scripts/transporter.py
This script acts as a ZMQ subscriber and packet forwarder to Wireshark via a named pipe (FIFO), allowing Wireshark to analyze packets in real time.

Main functionality:
- Connects to the ZMQ publisher (like collector.py) and subscribes to all incoming messages.
- For each received message:
  - Prints a hexdump for debugging purposes.
  - Wraps the data into a PCAP-compliant format using a custom link layer type.
  - Sends the formatted data to a named pipe, which Wireshark can be configured to read as a live packet source.
- Supports both Unix and Windows platforms (via PipeUnix and PipeWindows), although Windows support is still in development.
- Handles the creation and sending of a global PCAP header when the stream starts.
This script allows integration of custom packet data into Wireshark using a pipeline, enabling analysis and dissection of experimental or custom protocols.

For more information about how to configure GNU-Radio for meshtastic follow the next [repo](https://gitlab.com/crankylinuxuser/meshtastic_sdr). Just start the script with GNU-Radio and then connect the transporter.

To open wireshark add the path of the pipeline or execute the command:
```bash
wireshark -k -i /tmp/ftransporter  # If you change the value of the pipeline then use the new value
```

# Scripts/collector.py
This script acts as a ZMQ publisher that reads data from a serial interface (e.g., a development board) and publishes that data over a ZeroMQ PUB socket.

Main functionality:
- Opens a serial connection to a board with configurable port and baudrate.
- Sends a series of initialization commands to configure the board (e.g., frequency, spreading factor, power level).
- Sets the board into receive mode.
- Continuously reads lines from the serial port (typically LoRa packet data) and publishes each line over a ZeroMQ socket.
- Publishes to an address like tcp://localhost:20000 (by default), which can be changed via command-line arguments.
This script is useful for broadcasting received packets from a physical device to other systems or processes via ZeroMQ.


# Demo
![Demo using a lora usb stick board and the transporter](./static/trasnsporter_collector.gif)

## Special thanks for contribution:
  - Antonio Vázquez Blanco -> [Github](https://github.com/antoniovazquezblanco) | [X](https://x.com/antonvblanco)