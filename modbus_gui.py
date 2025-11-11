import tkinter as tk
from tkinter import ttk
import threading
import time
import subprocess
from modbus_client import load_config, create_modbus_client
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.constants import Endian

REGISTER_LIST = [
    {"address": 772, "label": "Control Mode", "type": "holding"},
    {"address": 48661, "label": "Gen Available LED", "type": "holding"},
    {"address": 48659, "label": "Breaker LED", "type": "holding"},
]

class ModbusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deep Sea Modbus Monitor")
        self.config = load_config()
        self.client = create_modbus_client(self.config)
        self.polling = False
        self.widgets = {}

        self.build_ui()
        threading.Thread(target=self.ping_ip, daemon=True).start()

    def build_ui(self):
        ttk.Label(self.root, text="Modbus TCP Monitor", font=("Segoe UI", 16)).grid(row=0, column=0, columnspan=4, pady=10)

        for i, reg in enumerate(REGISTER_LIST):
            ttk.Label(self.root, text=reg["label"]).grid(row=i+1, column=0, sticky="w", padx=10)
            val = ttk.Label(self.root, text="—", width=10, relief="sunken", anchor="center")
            val.grid(row=i+1, column=1, padx=10)
            self.widgets[reg["label"]] = val

        self.status = ttk.Label(self.root, text="Status: Disconnected", foreground="red")
        self.status.grid(row=len(REGISTER_LIST)+1, column=0, columnspan=2, pady=10)

        self.ping_label = ttk.Label(self.root, text="Ping: Checking...", foreground="gray")
        self.ping_label.grid(row=len(REGISTER_LIST)+2, column=0, columnspan=2)

        self.toggle_btn = ttk.Button(self.root, text="Start", command=self.toggle_polling)
        self.toggle_btn.grid(row=len(REGISTER_LIST)+3, column=0, columnspan=2, pady=5)

        # Page 166 Viewer
        ttk.Label(self.root, text="Page 166 Viewer", font=("Segoe UI", 12)).grid(row=0, column=2, columnspan=2, pady=10)
        ttk.Label(self.root, text="Start Reg").grid(row=1, column=2)
        ttk.Label(self.root, text="End Reg").grid(row=2, column=2)
        self.start_entry = ttk.Entry(self.root, width=10)
        self.end_entry = ttk.Entry(self.root, width=10)
        self.start_entry.grid(row=1, column=3)
        self.end_entry.grid(row=2, column=3)

        self.scan_btn = ttk.Button(self.root, text="Scan Page 166", command=self.scan_page_166)
        self.scan_btn.grid(row=3, column=2, columnspan=2, pady=5)

        self.page_output = tk.Text(self.root, width=50, height=20)
        self.page_output.grid(row=4, column=2, columnspan=2, padx=10, pady=5)

    def toggle_polling(self):
        if not self.polling:
            self.polling = True
            self.toggle_btn.config(text="Stop")
            self.status.config(text="Status: Connecting...", foreground="orange")
            threading.Thread(target=self.poll_loop, daemon=True).start()
        else:
            self.polling = False
            self.toggle_btn.config(text="Start")
            self.status.config(text="Status: Stopped", foreground="gray")

    def poll_loop(self):
        if not self.client.connect():
            self.status.config(text="Status: Connection Failed", foreground="red")
            return

        self.status.config(text="Status: Connected", foreground="green")

        while self.polling:
            for reg in REGISTER_LIST:
                try:
                    if reg["type"] == "input":
                        result = self.client.read_input_registers(reg["address"], 1, unit=self.config["slave_id"])
                    else:
                        result = self.client.read_holding_registers(reg["address"], 1, unit=self.config["slave_id"])
                    value = result.registers[0] if not result.isError() else "Error"
                except Exception:
                    value = "Error"
                self.widgets[reg["label"]].config(text=str(value))
            time.sleep(self.config["poll_interval"])

        self.client.close()

    def ping_ip(self):
        ip = self.config["tcp"]["ip"]
        while True:
            try:
                output = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
                if "TTL=" in output.stdout:
                    self.ping_label.config(text=f"Ping: Reachable ✅", foreground="green")
                else:
                    self.ping_label.config(text=f"Ping: Unreachable ❌", foreground="red")
            except Exception:
                self.ping_label.config(text=f"Ping: Error ❌", foreground="red")
            time.sleep(5)

    def scan_page_166(self):
        try:
            start = int(self.start_entry.get())
            end = int(self.end_entry.get())
        except ValueError:
            self.page_output.insert(tk.END, "Invalid register range.\n")
            return

        self.page_output.delete("1.0", tk.END)
        if not self.client.connect():
            self.page_output.insert(tk.END, "❌ Connection failed.\n")
            return

        for addr in range(start, end + 1):
            try:
                # Try reading 2 registers for float
                result = self.client.read_holding_registers(addr, 2, unit=self.config["slave_id"])
                if not result.isError():
                    decoder = BinaryPayloadDecoder.fromRegisters(result.registers, byteorder=Endian.Big, wordorder=Endian.Big)
                    float_val = decoder.decode_32bit_float()
                    if float_val != 0.0 and abs(float_val) < 1e6:
                        self.page_output.insert(tk.END, f"{addr}: {float_val:.2f} (float)\n")
                        continue

                # Fallback to 1 register for int
                result = self.client.read_holding_registers(addr, 1, unit=self.config["slave_id"])
                if not result.isError():
                    int_val = result.registers[0]
                    self.page_output.insert(tk.END, f"{addr}: {int_val} (int)\n")
                else:
                    self.page_output.insert(tk.END, f"{addr}: Error\n")
            except Exception:
                self.page_output.insert(tk.END, f"{addr}: Error\n")

        self.client.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = ModbusApp(root)
    root.mainloop()
