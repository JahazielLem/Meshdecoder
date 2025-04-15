def LOG_INFO(message):
  print(f"[INFO] {message}")

def LOG_ERROR(message):
  print(f"\x1b[31;1m[ERROR] {message}\x1b[0m")

def LOG_WARNING(message):
  print(f"\x1b[33;1m[WARNING] {message}\x1b[0m")

def LOG_SUCCESS(message):
  print(f"\x1b[32;1m[SUCCESS] {message}\x1b[0m")


def hexdump(data, width=16):
  hex_lines = []
  ascii_lines = []

  for i in range(0, len(data), width):
    chunk = data[i : i + width]
    hex_part = " ".join(f"{byte:02X}" for byte in chunk)
    ascii_part = "".join(
        chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
    )
    hex_lines.append(hex_part.ljust(width * 3))
    ascii_lines.append(ascii_part)

  return "\n".join(f"{h}  {a}" for h, a in zip(hex_lines, ascii_lines))