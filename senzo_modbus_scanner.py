import tkinter as tk
from tkinter import ttk, filedialog
from pymodbus.client.sync import ModbusTcpClient, ModbusSerialClient
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.constants import Endian
from datetime import datetime
import subprocess
import csv
import xml.etree.ElementTree as ET
import xlsxwriter
from fpdf import FPDF
import threading

class SenzoModbusScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Senzo Mashaba Modbus Scanner")
        self.scan_results = []
        self.client = None

        self.build_ui()
        threading.Thread(target=self.ping_loop, daemon=True).start()

    def build_ui(self):
        ttk.Label(self.root, text="Senzo Mashaba Modbus Scanner", font=("Segoe UI", 16)).grid(row=0, column=0, columnspan=4, pady=10)

        self.protocol_var = tk.StringVar(value="tcp")
        ttk.Label(self.root, text="Protocol").grid(row=1, column=0)
        ttk.OptionMenu(self.root, self.protocol_var, "tcp", "tcp", "rtu", command=self.update_fields).grid(row=1, column=1)

        ttk.Label(self.root, text="IP").grid(row=2, column=0)
        self.ip_entry = ttk.Entry(self.root)
        self.ip_entry.grid(row=2, column=1)

        ttk.Label(self.root, text="Port").grid(row=3, column=0)
        self.port_entry = ttk.Entry(self.root)
        self.port_entry.grid(row=3, column=1)

        ttk.Label(self.root, text="COM Port").grid(row=2, column=2)
        self.com_entry = ttk.Entry(self.root)
        self.com_entry.grid(row=2, column=3)

        ttk.Label(self.root, text="Baud Rate").grid(row=3, column=2)
        self.baud_entry = ttk.Entry(self.root)
        self.baud_entry.grid(row=3, column=3)

        ttk.Label(self.root, text="Start Reg").grid(row=4, column=0)
        self.start_entry = ttk.Entry(self.root)
        self.start_entry.grid(row=4, column=1)

        ttk.Label(self.root, text="End Reg").grid(row=4, column=2)
        self.end_entry = ttk.Entry(self.root)
        self.end_entry.grid(row=4, column=3)

        self.scan_btn = ttk.Button(self.root, text="Scan Page 166", command=self.scan_page_166)
        self.scan_btn.grid(row=5, column=0, columnspan=4, pady=5)

        self.output = tk.Text(self.root, width=80, height=20)
        self.output.grid(row=6, column=0, columnspan=4, padx=10, pady=5)

        ttk.Button(self.root, text="Export CSV", command=self.export_csv).grid(row=7, column=0)
        ttk.Button(self.root, text="Export XML", command=self.export_xml).grid(row=7, column=1)
        ttk.Button(self.root, text="Export Excel", command=self.export_excel).grid(row=7, column=2)
        ttk.Button(self.root, text="Export PDF", command=self.export_pdf).grid(row=7, column=3)

        self.ping_label = ttk.Label(self.root, text="Ping: Checking...", foreground="gray")
        self.ping_label.grid(row=8, column=0, columnspan=4)

        self.update_fields()

    def update_fields(self, *args):
        proto = self.protocol_var.get()
        if proto == "tcp":
            self.ip_entry.config(state="normal")
            self.port_entry.config(state="normal")
            self.com_entry.config(state="disabled")
            self.baud_entry.config(state="disabled")
        else:
            self.ip_entry.config(state="disabled")
            self.port_entry.config(state="disabled")
            self.com_entry.config(state="normal")
            self.baud_entry.config(state="normal")

    def ping_loop(self):
        while True:
            ip = self.ip_entry.get()
            if ip:
                try:
                    result = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
                    if "TTL=" in result.stdout:
                        self.ping_label.config(text="Ping: Reachable ✅", foreground="green")
                    else:
                        self.ping_label.config(text="Ping: Unreachable ❌", foreground="red")
                except:
                    self.ping_label.config(text="Ping: Error ❌", foreground="red")
            else:
                self.ping_label.config(text="Ping: No IP", foreground="gray")
            threading.Event().wait(5)

    def create_client(self):
        proto = self.protocol_var.get()
        if proto == "tcp":
            return ModbusTcpClient(
                host=self.ip_entry.get(),
                port=int(self.port_entry.get()),
                timeout=3
            )
        else:
            return ModbusSerialClient(
                method="rtu",
                port=self.com_entry.get(),
                baudrate=int(self.baud_entry.get()),
                parity="N",
                stopbits=1,
                bytesize=8,
                timeout=1
            )

    def scan_page_166(self):
        try:
            start = int(self.start_entry.get())
            end = int(self.end_entry.get())
        except:
            self.output.insert(tk.END, "Invalid register range.\n")
            return

        self.output.delete("1.0", tk.END)
        self.scan_results.clear()
        client = self.create_client()

        if not client.connect():
            self.output.insert(tk.END, "❌ Connection failed.\n")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.output.insert(tk.END, f"Senzo Mashaba Modbus Scanner\nScan Time: {timestamp}\n\n")

        for addr in range(start, end + 1):
            try:
                result = client.read_holding_registers(addr, 2, unit=1)
                if not result.isError():
                    decoder = BinaryPayloadDecoder.fromRegisters(result.registers, byteorder=Endian.Big, wordorder=Endian.Big)
                    float_val = decoder.decode_32bit_float()
                    if float_val != 0.0 and abs(float_val) < 1e6:
                        self.output.insert(tk.END, f"{addr}: {float_val:.2f} (float)\n")
                        self.scan_results.append((addr, float_val, "float"))
                        continue
                result = client.read_holding_registers(addr, 1, unit=1)
                if not result.isError():
                    int_val = result.registers[0]
                    self.output.insert(tk.END, f"{addr}: {int_val} (int)\n")
                    self.scan_results.append((addr, int_val, "int"))
                else:
                    self.output.insert(tk.END, f"{addr}: Error\n")
            except:
                self.output.insert(tk.END, f"{addr}: Error\n")

        client.close()

    def export_csv(self):
        file = filedialog.asksaveasfilename(defaultextension=".csv")
        if file:
            with open(file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Senzo Mashaba Modbus Scanner"])
                writer.writerow(["Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow(["Register", "Value", "Type"])
                for row in self.scan_results:
                    writer.writerow(row)

    def export_xml(self):
        file = filedialog.asksaveasfilename(defaultextension=".xml")
        if file:
            root = ET.Element("SenzoMashabaModbusScan")
            ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
            for addr, val, typ in self.scan_results:
                reg = ET.SubElement(root, "Register")
                ET.SubElement(reg, "Address").text = str(addr)
                ET.SubElement(reg, "Value").text = str(val)
                ET.SubElement(reg, "Type").text = typ
            tree = ET.ElementTree(root)
            tree.write(file)

    def export_excel(self):
        file = filedialog.asksaveasfilename(defaultextension=".xlsx")
        if file:
            workbook = xlsxwriter.Workbook(file)
            sheet = workbook.add_worksheet("Scan")
            sheet.write(0, 0, "Senzo Mashaba Modbus Scanner")
            sheet.write(1, 0, "Timestamp")
            sheet.write(1, 1, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            sheet.write(2, 0, "Register")
            sheet.write(2, 1, "Value")
            sheet.write(2, 2, "Type")
            for i, row in enumerate(self.scan_results, start=3):
                sheet.write(i, 0, row[0])
                sheet.write(i, 1, row[1])
                sheet.write(i, 2, row[2])
            workbook.close()

    def export_pdf(self):
        file = filedialog.asksaveasfilename(defaultextension=".pdf")
        if file:
            pdf = FPDF()
            pdf.add