#!/usr/bin/env python3
"""
Deep Sea Modbus Scanner - Asyncio background loop (works with pymodbus 2.5.3)
- Tkinter UI (non-blocking)
- Background asyncio loop in a thread
- Uses asyncio.to_thread for synchronous pymodbus calls
- Block reads for uint16 (fast), safe 2-register reads for int32/float32
- Removes single-register write UI (scan+export only)
Author: Senzo Mashaba (kept in exports)
"""

import asyncio
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.constants import Endian

# Expect user's modbus_client module to provide these; fallback stub provided
try:
    from modbus_client import load_config, create_modbus_client
except Exception:
    def load_config():
        return {
            "tcp": {"ip": "127.0.0.1", "port": 502},
            "rtu": {"port": "COM1", "baudrate": 9600, "parity": "N", "stopbits": 1, "serial_mode": "RS485"},
            "slave_id": 1,
            "poll_interval": 5
        }
    def create_modbus_client(config):
        raise RuntimeError("create_modbus_client must be provided in modbus_client module")

# Exports libs
try:
    import xlsxwriter
    from fpdf import FPDF
except Exception:
    xlsxwriter = None
    FPDF = None

# pyserial ports listing
try:
    import serial.tools.list_ports as list_ports
except Exception:
    list_ports = None

# Logging
logger = logging.getLogger("dse_scanner")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("dse_scanner.log"), logging.StreamHandler()]
)

# Constants
COM_PORTS = [f"COM{i}" for i in range(10)]
BAUD_RATES = [9600, 19200, 38400, 57600, 115200]
SLAVE_IDS = list(range(1, 11))
SERIAL_MODES = ["RS232", "RS485"]
MAX_REGISTERS_TO_SCAN = 1000

# ---------- Low-level read helpers (synchronous; safe to call in threads) ----------
class RawRegisterReader:
    @staticmethod
    def read_register(client, address, count, slave_id):
        """
        Blocking read using client.read_holding_registers. Defensive checks.
        """
        try:
            result = client.read_holding_registers(address, count, unit=slave_id)
            if result is None:
                return {"value": "Error: No response", "registers": [], "type": "error"}
            if hasattr(result, "isError") and result.isError():
                return {"value": "Error", "registers": [], "type": "error"}
            regs = getattr(result, "registers", None)
            if regs is None:
                try:
                    regs = list(result)
                except Exception:
                    return {"value": "Error: No registers", "registers": [], "type": "error"}
            regs = [int(r) & 0xFFFF for r in regs]
            if count == 1:
                return {"value": regs[0], "registers": regs, "type": "uint16"}
            if count == 2:
                return {"value": f"[{regs[0]}, {regs[1]}]", "registers": regs, "type": "uint32_raw"}
            return {"value": regs, "registers": regs, "type": "raw"}
        except Exception as e:
            logger.exception("read_register exception")
            return {"value": f"Error: {e}", "registers": [], "type": "error"}

    @staticmethod
    def read_as_int16(client, address, slave_id):
        return RawRegisterReader.read_register(client, address, 1, slave_id)

    @staticmethod
    def read_as_int32(client, address, slave_id):
        r = RawRegisterReader.read_register(client, address, 2, slave_id)
        if r["type"] != "error" and len(r["registers"]) == 2:
            high, low = r["registers"][0], r["registers"][1]
            val = (high << 16) | (low & 0xFFFF)
            if val & 0x80000000:
                val = val - (1 << 32)
            r["value"] = val
            r["type"] = "int32"
        return r

    @staticmethod
    def read_as_float32(client, address, slave_id):
        r = RawRegisterReader.read_register(client, address, 2, slave_id)
        if r["type"] != "error" and len(r["registers"]) == 2:
            try:
                decoder = BinaryPayloadDecoder.fromRegisters(r["registers"], byteorder=Endian.Big, wordorder=Endian.Big)
                fv = decoder.decode_32bit_float()
                r["value"] = fv
                r["type"] = "float32"
            except Exception:
                try:
                    decoder = BinaryPayloadDecoder.fromRegisters(r["registers"], byteorder=Endian.Big, wordorder=Endian.Little)
                    fv = decoder.decode_32bit_float()
                    r["value"] = fv
                    r["type"] = "float32"
                except Exception:
                    r["value"] = "Not a float"
                    r["type"] = "error"
        return r

# ---------- App ----------
class ModbusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deep Sea Modbus Scanner - Async (Background Loop)")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # load config
        try:
            self.config = load_config()
        except Exception as e:
            logger.warning("load_config failed, using defaults: %s", e)
            self.config = {
                "tcp": {"ip": "127.0.0.1", "port": 502},
                "rtu": {"port": "COM1", "baudrate": 9600, "parity": "N", "stopbits": 1, "serial_mode": "RS485"},
                "slave_id": 1,
                "poll_interval": 5
            }

        if not self._validate_config():
            messagebox.showerror("Config Error", "Invalid config keys")
            self.root.destroy()
            return

        # state
        self.scan_results = []
        self.scanning = False
        self.client = None

        # asyncio loop in background thread
        self.loop = asyncio.new_event_loop()
        self.loop_thread = threading.Thread(target=self._start_loop, daemon=True)
        self.loop_thread.start()

        # vars
        self.protocol_var = tk.StringVar(value=self.config.get("protocol", "tcp"))
        self.com_port_var = tk.StringVar(value=self.config["rtu"].get("port", "COM1"))
        self.baud_rate_var = tk.StringVar(value=str(self.config["rtu"].get("baudrate", 9600)))
        self.slave_id_var = tk.StringVar(value=str(self.config.get("slave_id", 1)))
        self.serial_mode_var = tk.StringVar(value=self.config["rtu"].get("serial_mode", "RS485"))
        self.data_type_var = tk.StringVar(value="uint16")
        # block size for uint16 reads
        self.block_size = tk.IntVar(value=50)  # default block read size for uint16

        # build UI
        self.build_ui()

        # start ping task on loop
        asyncio.run_coroutine_threadsafe(self.ping_ip_task(), self.loop)

    def _start_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _validate_config(self):
        for k in ["tcp", "rtu", "slave_id", "poll_interval"]:
            if k not in self.config:
                logger.error("missing config key: %s", k)
                return False
        return True

    def on_closing(self):
        logger.info("Closing app...")
        # stop scanning
        self.scanning = False
        # cancel tasks and stop loop
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:
            pass
        try:
            if self.client:
                try:
                    self.client.close()
                except Exception:
                    pass
        except Exception:
            pass
        self.root.destroy()
        logger.info("Closed")

    def build_ui(self):
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        right = ttk.Frame(main)
        right.grid(row=0, column=1, sticky="ns")

        main.columnconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(8, weight=1)

        # Title
        tf = ttk.Frame(left)
        tf.grid(row=0, column=0, columnspan=4, pady=(0,10))
        ttk.Label(tf, text="Deep Sea Modbus Scanner - Immediate Update", font=("Segoe UI", 16, "bold")).pack()
        ttk.Label(tf, text="by Senzo Mashaba", font=("Segoe UI", 10, "italic"), foreground="gray").pack()

        # Protocol
        ttk.Label(left, text="Protocol").grid(row=1, column=0, sticky="w", padx=5)
        proto = ttk.Combobox(left, textvariable=self.protocol_var, values=["tcp","rtu"], state="readonly", width=10)
        proto.grid(row=1, column=1, sticky="w", padx=5)
        proto.bind("<<ComboboxSelected>>", lambda e: self._on_protocol_change())

        # TCP
        tcp_frame = ttk.LabelFrame(left, text="TCP Configuration", padding=5)
        tcp_frame.grid(row=2, column=0, columnspan=4, sticky="we", padx=5, pady=5)
        ttk.Label(tcp_frame, text="IP Address").grid(row=0, column=0, sticky="w", padx=5)
        self.ip_entry = ttk.Entry(tcp_frame, width=15); self.ip_entry.insert(0, self.config["tcp"]["ip"]); self.ip_entry.grid(row=0,column=1)
        ttk.Label(tcp_frame, text="Port").grid(row=0, column=2, sticky="w", padx=5)
        self.port_entry = ttk.Entry(tcp_frame, width=8); self.port_entry.insert(0, str(self.config["tcp"].get("port",502))); self.port_entry.grid(row=0,column=3)

        # RTU
        rtu_frame = ttk.LabelFrame(left, text="RTU Configuration", padding=5)
        rtu_frame.grid(row=3, column=0, columnspan=4, sticky="we", padx=5, pady=5)
        ttk.Label(rtu_frame, text="COM Port").grid(row=0, column=0, sticky="w", padx=5)
        self.com_combo = ttk.Combobox(rtu_frame, textvariable=self.com_port_var, values=COM_PORTS, state="readonly", width=8)
        self.com_combo.grid(row=0,column=1)
        ttk.Label(rtu_frame, text="Baud Rate").grid(row=0, column=2, sticky="w", padx=5)
        ttk.Combobox(rtu_frame, textvariable=self.baud_rate_var, values=BAUD_RATES, state="readonly", width=8).grid(row=0,column=3)
        ttk.Label(rtu_frame, text="Slave ID").grid(row=1, column=0, sticky="w", padx=5)
        ttk.Combobox(rtu_frame, textvariable=self.slave_id_var, values=SLAVE_IDS, state="readonly", width=8).grid(row=1,column=1)
        ttk.Label(rtu_frame, text="Serial Mode").grid(row=1, column=2, sticky="w", padx=5)
        ttk.Combobox(rtu_frame, textvariable=self.serial_mode_var, values=SERIAL_MODES, state="readonly", width=8).grid(row=1,column=3)
        ttk.Label(rtu_frame, text="Parity").grid(row=2, column=0, sticky="w", padx=5)
        self.parity_var = tk.StringVar(value=self.config["rtu"].get("parity","N"))
        ttk.Combobox(rtu_frame, textvariable=self.parity_var, values=["N","E","O"], state="readonly", width=5).grid(row=2,column=1)
        ttk.Label(rtu_frame, text="Stop Bits").grid(row=2, column=2, sticky="w", padx=5)
        self.stop_bits_var = tk.StringVar(value=str(self.config["rtu"].get("stopbits",1)))
        ttk.Combobox(rtu_frame, textvariable=self.stop_bits_var, values=[1,1.5,2], state="readonly", width=5).grid(row=2,column=3)

        # Status
        sf = ttk.Frame(left); sf.grid(row=4,column=0,columnspan=4,sticky="we", padx=5, pady=5)
        self.status = ttk.Label(sf, text="Status: Ready", foreground="green"); self.status.grid(row=0,column=0,sticky="w")
        self.ping_label = ttk.Label(sf, text="Ping: Checking...", foreground="gray"); self.ping_label.grid(row=0,column=1,sticky="w", padx=20)
        ttk.Button(sf, text="Refresh COM Ports", command=self.refresh_com_ports).grid(row=0,column=2,padx=5)

        # Scanner
        scan_frame = ttk.LabelFrame(left, text=f"Register Scanner (Max: {MAX_REGISTERS_TO_SCAN})", padding=5)
        scan_frame.grid(row=5,column=0,columnspan=4,sticky="we", padx=5, pady=5)
        ttk.Label(scan_frame, text="Start Register").grid(row=0,column=0,sticky="w", padx=5)
        self.start_entry = ttk.Entry(scan_frame,width=10); self.start_entry.insert(0,"0"); self.start_entry.grid(row=0,column=1)
        ttk.Label(scan_frame, text="End Register").grid(row=0,column=2,sticky="w", padx=5)
        self.end_entry = ttk.Entry(scan_frame,width=10); self.end_entry.insert(0,"100"); self.end_entry.grid(row=0,column=3)
        ttk.Label(scan_frame, text="Read As").grid(row=1,column=0,sticky="w", padx=5)
        ttk.Combobox(scan_frame, textvariable=self.data_type_var, values=["uint16","int32","float32"], state="readonly", width=10).grid(row=1,column=1)
        ttk.Label(scan_frame, text="Block size (uint16)").grid(row=1,column=2,sticky="w", padx=5)
        ttk.Entry(scan_frame, textvariable=self.block_size, width=6).grid(row=1,column=3, sticky="w")

        self.scan_btn = ttk.Button(scan_frame, text="Start Scan", command=self.toggle_scan, width=15); self.scan_btn.grid(row=2,column=2,padx=5,pady=5)

        # Progress and output
        pf = ttk.Frame(left); pf.grid(row=7,column=0,columnspan=4, sticky="we", pady=5)
        self.progress = ttk.Progressbar(pf, mode="determinate"); self.progress.pack(fill="x", padx=5)
        self.progress_label = ttk.Label(pf, text="Ready to scan"); self.progress_label.pack()
        of = ttk.LabelFrame(left, text="Scan Results", padding=5); of.grid(row=8,column=0,columnspan=4, sticky="nsew", padx=5, pady=5)
        self.page_output = tk.Text(of, width=70, height=25); self.page_output.pack(fill="both", expand=True, padx=5, pady=5)

        # Exports
        ef = ttk.LabelFrame(right, text="Export Data", padding=10); ef.pack(pady=20)
        ttk.Button(ef, text="Export CSV", command=self.export_csv, width=15).pack(pady=5, padx=10, fill="x")
        ttk.Button(ef, text="Export XML", command=self.export_xml, width=15).pack(pady=5, padx=10, fill="x")
        ttk.Button(ef, text="Export Excel", command=self.export_excel, width=15).pack(pady=5, padx=10, fill="x")
        ttk.Button(ef, text="Export PDF", command=self.export_pdf, width=15).pack(pady=5, padx=10, fill="x")
        ttk.Button(right, text="Quick Rescan", command=self.quick_rescan, width=15).pack(pady=10, padx=10, fill="x")
        ttk.Label(right, text="by Senzo Mashaba", font=("Segoe UI",8,"italic"), foreground="gray").pack(side="bottom", pady=10)

        self._on_protocol_change()

    def _on_protocol_change(self):
        if self.protocol_var.get() == "tcp":
            self.ip_entry.config(state="normal"); self.port_entry.config(state="normal")
            self.com_combo.config(state="disabled")
        else:
            self.ip_entry.config(state="disabled"); self.port_entry.config(state="disabled")
            self.com_combo.config(state="readonly")

    def update_config_from_ui(self):
        self.config["tcp"]["ip"] = self.ip_entry.get()
        try:
            self.config["tcp"]["port"] = int(self.port_entry.get())
        except Exception:
            pass
        self.config["rtu"]["port"] = self.com_port_var.get()
        try:
            self.config["rtu"]["baudrate"] = int(self.baud_rate_var.get())
        except Exception:
            pass
        self.config["rtu"]["parity"] = self.parity_var.get()
        try:
            self.config["rtu"]["stopbits"] = float(self.stop_bits_var.get())
        except Exception:
            pass
        self.config["rtu"]["serial_mode"] = self.serial_mode_var.get()
        try:
            self.config["slave_id"] = int(self.slave_id_var.get())
        except Exception:
            pass

    def validate_register_range(self, start, end):
        total = end - start + 1
        if total > MAX_REGISTERS_TO_SCAN:
            return False, f"Scan range too large: {total}, max {MAX_REGISTERS_TO_SCAN}"
        if start < 0 or end < 0:
            return False, "Register addresses cannot be negative"
        if start > end:
            return False, "Start must be <= end"
        return True, f"Valid range: {total} registers"

    def toggle_scan(self):
        if not self.scanning:
            self.start_scan()
        else:
            self.stop_scanning()

    def start_scan(self):
        try:
            start = int(self.start_entry.get()); end = int(self.end_entry.get())
            data_type = self.data_type_var.get()
        except Exception:
            self.page_output.insert(tk.END, "❌ Invalid register range format.\n"); return

        ok, msg = self.validate_register_range(start, end)
        if not ok:
            self.page_output.insert(tk.END, f"❌ {msg}\n"); return

        self.update_config_from_ui()
        self.page_output.delete("1.0", tk.END)
        self.scan_results.clear()
        self.scanning = True
        self.scan_btn.config(text="Stop Scan")
        self.status.config(text="Status: Scanning...", foreground="orange")

        # schedule scan coroutine on background loop
        fut = asyncio.run_coroutine_threadsafe(self.scan_registers_task(start, end, data_type), self.loop)
        # store future if needed
        self.current_scan_future = fut

    def stop_scanning(self):
        self.scanning = False
        try:
            if hasattr(self, "current_scan_future") and not self.current_scan_future.done():
                self.current_scan_future.cancel()
        except Exception:
            pass
        self.scan_btn.config(text="Start Scan")
        self.status.config(text="Status: Scan Stopped", foreground="red")
        self.progress_label.config(text="Scan stopped by user")

    def quick_rescan(self):
        if self.scan_results:
            addrs = [r["address"] for r in self.scan_results]
            if addrs:
                s, e = min(addrs), max(addrs)
                self.start_entry.delete(0, tk.END); self.start_entry.insert(0, str(s))
                self.end_entry.delete(0, tk.END); self.end_entry.insert(0, str(e))
                self.start_scan()
                return
        messagebox.showinfo("Quick Rescan", "No previous results to rescan.")

    # ---------- Core scanning task ----------
    async def scan_registers_task(self, start, end, data_type):
        """
        Runs on the background asyncio loop. Uses asyncio.to_thread for blocking calls.
        Strategy:
         - For uint16: use block reads of size self.block_size (faster).
         - For int32/float32: read 2 registers at a time (skip next).
        """
        self.update_config_from_ui()
        slave = int(self.config.get("slave_id", 1))

        # create client via blocking factory
        try:
            client = await asyncio.to_thread(create_modbus_client, self.config)
        except Exception as e:
            logger.exception("create_modbus_client failed")
            self.root.after(0, lambda: self.page_output.insert(tk.END, f"❌ Failed to create client: {e}\n"))
            self.root.after(0, lambda: self.status.config(text="Status: Client Error", foreground="red"))
            self.scanning = False
            self.scan_btn.config(text="Start Scan")
            return

        # attempt connect (blocking)
        try:
            connected = await asyncio.to_thread(client.connect)
        except Exception as e:
            logger.warning("connect raised: %s", e)
            connected = False

        if not connected:
            self.root.after(0, lambda: self.page_output.insert(tk.END, "❌ Connection failed.\n"))
            self.root.after(0, lambda: self.status.config(text="Status: Connection Failed", foreground="red"))
            self.scanning = False
            self.scan_btn.config(text="Start Scan")
            try:
                await asyncio.to_thread(client.close)
            except Exception:
                pass
            return

        self.client = client  # keep reference to close later
        conn_info = f"RTU {self.config['rtu']['port']}" if self.protocol_var.get()=="rtu" else f"IP {self.config['tcp']['ip']}:{self.config['tcp'].get('port',502)}"
        total = end - start + 1
        self.root.after(0, lambda: self.page_output.insert(tk.END, f"🔧 Connection: {conn_info}\n"))
        self.root.after(0, lambda: self.page_output.insert(tk.END, f"📊 Scanning registers {start} - {end} as {data_type}...\n"))
        self.root.after(0, lambda: self.page_output.insert(tk.END, f"📈 Total: {total}\n\n"))
        self.root.after(0, lambda: self.progress.config(maximum=total, value=0))

        successful = 0; failed = 0
        scanned = 0
        addr = start

        try:
            if data_type == "uint16":
                blk = max(1, int(self.block_size.get()))
                while addr <= end and self.scanning:
                    # compute how many to read in this block
                    remain = end - addr + 1
                    to_read = min(blk, remain)
                    # perform blocking block read inside thread
                    try:
                        res = await asyncio.to_thread(RawRegisterReader.read_register, client, addr, to_read, slave)
                    except Exception as e:
                        logger.exception("block read exception")
                        # write each address as error for this block
                        for a in range(addr, addr+to_read):
                            self.scan_results.append({"address": a, "value": f"Error: {type(e).__name__}", "type": "uint16", "status":"error"})
                            self.root.after(0, lambda txt=f"Register {a:6d}: ❌ Read Error\n": self.page_output.insert(tk.END, txt))
                            failed += 1
                            scanned += 1
                        addr += to_read
                        # update progress
                        self.root.after(0, lambda v=min(scanned,total): self.progress.config(value=v))
                        self.root.after(0, lambda txt=f"Scanning... {min(scanned,total)}/{total}": self.progress_label.config(text=txt))
                        await asyncio.sleep(0) 
                        continue

                    # res holds .registers if count>1; adapt to block output
                    if res["type"] == "error":
                        # mark block as errors
                        for a in range(addr, addr+to_read):
                            self.scan_results.append({"address": a, "value": res.get("value"), "type": "uint16", "status":"error"})
                            self.root.after(0, lambda txt=f"Register {a:6d}: ❌ Read Error\n": self.page_output.insert(tk.END, txt))
                            failed += 1
                            scanned += 1
                    else:
                        # result['registers'] is list of ints
                        regs = res.get("registers", [])
                        for i, r in enumerate(regs):
                            a = addr + i
                            self.scan_results.append({"address": a, "value": r, "type":"uint16", "status":"success"})
                            self.root.after(0, lambda txt=f"Register {a:6d}: {r}\n": self.page_output.insert(tk.END, txt))
                            successful += 1
                            scanned += 1

                    addr += to_read
                    # progress update
                    self.root.after(0, lambda v=min(scanned,total): self.progress.config(value=v))
                    self.root.after(0, lambda txt=f"Scanning... {min(scanned,total)}/{total}": self.progress_label.config(text=txt))
                    await asyncio.sleep(0)  # yield to loop

            else:
                # int32 or float32: read two registers per address (skip the next)
                step = 2
                read_fn = RawRegisterReader.read_as_int32 if data_type == "int32" else RawRegisterReader.read_as_float32
                while addr <= end and self.scanning:
                    # ensure addr+1 <= end for 2-register read; if not, mark error and break
                    if addr + 1 > end:
                        # cannot read 2 registers at end; mark last as error
                        self.scan_results.append({"address": addr, "value": "Insufficient registers for 2-register read", "type": data_type, "status":"error"})
                        self.root.after(0, lambda txt=f"Register {addr:6d}: ❌ Insufficient registers for 2-register read\n": self.page_output.insert(tk.END, txt))
                        failed += 1
                        scanned += 1
                        self.root.after(0, lambda v=min(scanned,total): self.progress.config(value=v))
                        self.root.after(0, lambda txt=f"Scanning... {min(scanned,total)}/{total}": self.progress_label.config(text=txt))
                        break

                    try:
                        res = await asyncio.to_thread(read_fn, client, addr, slave)
                    except Exception as e:
                        logger.exception("2-register read exception")
                        res = {"value": f"Error: {e}", "registers": [], "type": "error"}

                    if res.get("type") != "error" and not str(res.get("value","")).startswith("Error"):
                        self.scan_results.append({"address": addr, "value": res["value"], "type": data_type, "status":"success"})
                        self.root.after(0, lambda txt=f"Register {addr:6d}: {res['value']}\n": self.page_output.insert(tk.END, txt))
                        successful += 1
                    else:
                        self.scan_results.append({"address": addr, "value": res.get("value"), "type": data_type, "status":"error"})
                        self.root.after(0, lambda txt=f"Register {addr:6d}: ❌ Read Error\n": self.page_output.insert(tk.END, txt))
                        failed += 1

                    addr += step
                    scanned += step
                    self.root.after(0, lambda v=min(scanned,total): self.progress.config(value=v))
                    self.root.after(0, lambda txt=f"Scanning... {min(scanned,total)}/{total}": self.progress_label.config(text=txt))
                    await asyncio.sleep(0)  # yield

        except asyncio.CancelledError:
            logger.info("scan_registers_task cancelled")
        except Exception:
            logger.exception("Unhandled exception in scan_registers_task")
        finally:
            try:
                await asyncio.to_thread(client.close)
            except Exception:
                pass

            if self.scanning:
                summary = "\n📋 Scan Complete:\n"
                summary += f"✅ Successful reads: {successful}\n"
                summary += f"❌ Failed reads: {failed}\n"
                summary += f"📈 Total registers scanned: {len(self.scan_results)}\n"
                self.root.after(0, lambda: self.page_output.insert(tk.END, summary))
                self.root.after(0, lambda: self.status.config(text="Status: Scan Complete", foreground="green"))
                self.root.after(0, lambda: self.progress_label.config(text="Scan complete"))
            else:
                self.root.after(0, lambda: self.status.config(text="Status: Scan Stopped", foreground="red"))
                self.root.after(0, lambda: self.progress_label.config(text="Scan stopped"))

            self.scan_btn.config(text="Start Scan")
            self.scanning = False
            self.client = None

    # ---------- Ping task ----------
    async def ping_ip_task(self):
        import subprocess
        ip = self.config["tcp"].get("ip", "127.0.0.1")
        while True:
            try:
                if self.protocol_var.get() == "tcp":
                    cmd = ["ping", "-n", "1", ip] if subprocess.os.name == "nt" else ["ping", "-c", "1", ip]
                    try:
                        proc = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True, timeout=5)
                        out = proc.stdout or ""
                        reachable = "TTL=" in out or "ttl=" in out
                        status_text = "Ping: Reachable ✅" if reachable else "Ping: Unreachable ❌"
                        color = "green" if reachable else "red"
                        self.root.after(0, lambda txt=status_text, col=color: self.ping_label.config(text=txt, foreground=col))
                    except Exception:
                        self.root.after(0, lambda: self.ping_label.config(text="Ping: Error ❌", foreground="red"))
                else:
                    self.root.after(0, lambda: self.ping_label.config(text="Serial: RTU Mode", foreground="blue"))
            except Exception:
                logger.exception("ping task exception")
            await asyncio.sleep(5)

    # ---------- COM ports ----------
    def refresh_com_ports(self):
        if list_ports is None:
            messagebox.showinfo("Refresh COM Ports", "pyserial missing; install pyserial to enable COM refresh")
            return
        try:
            ports = [p.device for p in list_ports.comports()]
            if ports:
                self.com_combo.config(values=ports)
                messagebox.showinfo("Refresh COM Ports", "COM ports refreshed")
            else:
                messagebox.showinfo("Refresh COM Ports", "No COM ports found")
        except Exception as e:
            messagebox.showerror("Refresh COM Ports", f"Error listing ports: {e}")
            logger.exception("refresh_com_ports failed")

    # ---------- Exports ----------
    def export_csv(self):
        if not self.scan_results:
            messagebox.showinfo("Export CSV", "No results to export")
            return
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not file:
            return
        try:
            with open(file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Deep Sea Modbus Scanner - Immediate Update"])
                writer.writerow(["by Senzo Mashaba"])
                writer.writerow([])
                writer.writerow(["Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow(["Protocol", self.protocol_var.get()])
                writer.writerow(["Maximum Scan Limit", MAX_REGISTERS_TO_SCAN])
                if self.protocol_var.get()=="rtu":
                    writer.writerow(["COM Port", self.com_port_var.get()])
                    writer.writerow(["Baud Rate", self.baud_rate_var.get()])
                    writer.writerow(["Slave ID", self.slave_id_var.get()])
                else:
                    writer.writerow(["IP Address", self.ip_entry.get()])
                    writer.writerow(["Port", self.port_entry.get()])
                writer.writerow([])
                writer.writerow(["Register","Value","Data Type","Status"])
                for it in self.scan_results:
                    writer.writerow([it["address"], it["value"], it["type"], it["status"]])
            messagebox.showinfo("Export CSV", f"Exported to {file}")
        except Exception:
            logger.exception("CSV export failed")
            messagebox.showerror("Export CSV", "Failed to write CSV")

    def export_xml(self):
        if not self.scan_results:
            messagebox.showinfo("Export XML", "No results to export"); return
        file = filedialog.asksaveasfilename(defaultextension=".xml", filetypes=[("XML","*.xml")])
        if not file: return
        try:
            root = ET.Element("ModbusScan")
            app = ET.SubElement(root, "ApplicationInfo")
            ET.SubElement(app, "Application").text = "Deep Sea Modbus Scanner - Immediate Update"
            ET.SubElement(app, "Author").text = "Senzo Mashaba"
            ET.SubElement(app, "ExportTimestamp").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            meta = ET.SubElement(root, "Metadata")
            ET.SubElement(meta, "Timestamp").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ET.SubElement(meta, "Protocol").text = self.protocol_var.get()
            ET.SubElement(meta, "MaximumScanLimit").text = str(MAX_REGISTERS_TO_SCAN)
            if self.protocol_var.get()=="rtu":
                ET.SubElement(meta, "COMPort").text = self.com_port_var.get()
                ET.SubElement(meta, "BaudRate").text = self.baud_rate_var.get()
                ET.SubElement(meta, "SlaveID").text = self.slave_id_var.get()
            else:
                ET.SubElement(meta, "IPAddress").text = self.ip_entry.get()
                ET.SubElement(meta, "Port").text = self.port_entry.get()
            results = ET.SubElement(root, "Results")
            for it in self.scan_results:
                item = ET.SubElement(results, "Item")
                ET.SubElement(item, "Register").text = str(it["address"])
                ET.SubElement(item, "Value").text = str(it["value"])
                ET.SubElement(item, "DataType").text = it["type"]
                ET.SubElement(item, "Status").text = it["status"]
            tree = ET.ElementTree(root); tree.write(file, encoding="utf-8", xml_declaration=True)
            messagebox.showinfo("Export XML", f"Exported to {file}")
        except Exception:
            logger.exception("XML export failed")
            messagebox.showerror("Export XML", "Failed to write XML")

    def export_excel(self):
        if xlsxwriter is None:
            messagebox.showinfo("Export Excel", "xlsxwriter not installed"); return
        if not self.scan_results:
            messagebox.showinfo("Export Excel", "No results"); return
        file = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel","*.xlsx")])
        if not file: return
        try:
            wb = xlsxwriter.Workbook(file); ws = wb.add_worksheet("Scan Results")
            bold = wb.add_format({"bold": True})
            title = wb.add_format({"bold": True, "font_size": 14})
            auth = wb.add_format({"italic": True, "font_color": "gray"})
            ws.write("A1","Deep Sea Modbus Scanner - Immediate Update", title)
            ws.write("A2","by Senzo Mashaba", auth); ws.write("A3","")
            ws.write("A4","Timestamp", bold); ws.write("B4", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            ws.write("A5","Protocol", bold); ws.write("B5", self.protocol_var.get())
            ws.write("A6","Maximum Scan Limit", bold); ws.write("B6", MAX_REGISTERS_TO_SCAN)
            start_row = 10
            ws.write(f"A{start_row}","Register", bold); ws.write(f"B{start_row}","Value", bold)
            ws.write(f"C{start_row}","Data Type", bold); ws.write(f"D{start_row}","Status", bold)
            row = start_row + 1
            for it in self.scan_results:
                ws.write(row,0,it["address"]); ws.write(row,1,str(it["value"])); ws.write(row,2,it["type"]); ws.write(row,3,it["status"])
                row += 1
            wb.close(); messagebox.showinfo("Export Excel", f"Exported to {file}")
        except Exception:
            logger.exception("Excel export failed"); messagebox.showerror("Export Excel", "Failed to write Excel")

    def export_pdf(self):
        if FPDF is None:
            messagebox.showinfo("Export PDF", "fpdf not installed"); return
        if not self.scan_results:
            messagebox.showinfo("Export PDF", "No results"); return
        file = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF","*.pdf")])
        if not file: return
        try:
            pdf = FPDF(); pdf.set_auto_page_break(auto=True, margin=15); pdf.add_page()
            pdf.set_font("Arial","B",16); pdf.cell(0,10,"Deep Sea Modbus Scanner - Immediate Update", ln=True)
            pdf.set_font("Arial","I",12); pdf.cell(0,8,"by Senzo Mashaba", ln=True); pdf.ln(5)
            pdf.set_font("Arial","",11); pdf.cell(0,8,f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.cell(0,8,f"Protocol: {self.protocol_var.get()}", ln=True); pdf.ln(4)
            pdf.set_font("Arial","B",11); pdf.cell(30,8,"Register", border=1); pdf.cell(60,8,"Value", border=1); pdf.cell(30,8,"Data Type", border=1); pdf.cell(30,8,"Status", border=1, ln=True)
            pdf.set_font("Arial","",11)
            for it in self.scan_results:
                pdf.cell(30,8,str(it["address"]), border=1); pdf.cell(60,8,str(it["value"]), border=1)
                pdf.cell(30,8,it["type"], border=1); pdf.cell(30,8,it["status"], border=1, ln=True)
            pdf.output(file); messagebox.showinfo("Export PDF", f"Exported to {file}")
        except Exception:
            logger.exception("PDF export failed"); messagebox.showerror("Export PDF", "Failed to write PDF")

# ---------- Run ----------
def main():
    root = tk.Tk()
    app = ModbusApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Deep Sea Modbus Scanner - Asyncio background loop (works with pymodbus 2.5.3)
- Tkinter UI (non-blocking)
- Background asyncio loop in a thread
- Uses asyncio.to_thread for synchronous pymodbus calls
- Block reads for uint16 (fast), safe 2-register reads for int32/float32
- Removes single-register write UI (scan+export only)
Author: Senzo Mashaba (kept in exports)
"""

import asyncio
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.constants import Endian

# Expect user's modbus_client module to provide these; fallback stub provided
try:
    from modbus_client import load_config, create_modbus_client
except Exception:
    def load_config():
        return {
            "tcp": {"ip": "127.0.0.1", "port": 502},
            "rtu": {"port": "COM1", "baudrate": 9600, "parity": "N", "stopbits": 1, "serial_mode": "RS485"},
            "slave_id": 1,
            "poll_interval": 5
        }
    def create_modbus_client(config):
        raise RuntimeError("create_modbus_client must be provided in modbus_client module")

# Exports libs
try:
    import xlsxwriter
    from fpdf import FPDF
except Exception:
    xlsxwriter = None
    FPDF = None

# pyserial ports listing
try:
    import serial.tools.list_ports as list_ports
except Exception:
    list_ports = None

# Logging
logger = logging.getLogger("dse_scanner")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("dse_scanner.log"), logging.StreamHandler()]
)

# Constants
COM_PORTS = [f"COM{i}" for i in range(10)]
BAUD_RATES = [9600, 19200, 38400, 57600, 115200]
SLAVE_IDS = list(range(1, 11))
SERIAL_MODES = ["RS232", "RS485"]
MAX_REGISTERS_TO_SCAN = 1000

# ---------- Low-level read helpers (synchronous; safe to call in threads) ----------
class RawRegisterReader:
    @staticmethod
    def read_register(client, address, count, slave_id):
        """
        Blocking read using client.read_holding_registers. Defensive checks.
        """
        try:
            result = client.read_holding_registers(address, count, unit=slave_id)
            if result is None:
                return {"value": "Error: No response", "registers": [], "type": "error"}
            if hasattr(result, "isError") and result.isError():
                return {"value": "Error", "registers": [], "type": "error"}
            regs = getattr(result, "registers", None)
            if regs is None:
                try:
                    regs = list(result)
                except Exception:
                    return {"value": "Error: No registers", "registers": [], "type": "error"}
            regs = [int(r) & 0xFFFF for r in regs]
            if count == 1:
                return {"value": regs[0], "registers": regs, "type": "uint16"}
            if count == 2:
                return {"value": f"[{regs[0]}, {regs[1]}]", "registers": regs, "type": "uint32_raw"}
            return {"value": regs, "registers": regs, "type": "raw"}
        except Exception as e:
            logger.exception("read_register exception")
            return {"value": f"Error: {e}", "registers": [], "type": "error"}

    @staticmethod
    def read_as_int16(client, address, slave_id):
        return RawRegisterReader.read_register(client, address, 1, slave_id)

    @staticmethod
    def read_as_int32(client, address, slave_id):
        r = RawRegisterReader.read_register(client, address, 2, slave_id)
        if r["type"] != "error" and len(r["registers"]) == 2:
            high, low = r["registers"][0], r["registers"][1]
            val = (high << 16) | (low & 0xFFFF)
            if val & 0x80000000:
                val = val - (1 << 32)
            r["value"] = val
            r["type"] = "int32"
        return r

    @staticmethod
    def read_as_float32(client, address, slave_id):
        r = RawRegisterReader.read_register(client, address, 2, slave_id)
        if r["type"] != "error" and len(r["registers"]) == 2:
            try:
                decoder = BinaryPayloadDecoder.fromRegisters(r["registers"], byteorder=Endian.Big, wordorder=Endian.Big)
                fv = decoder.decode_32bit_float()
                r["value"] = fv
                r["type"] = "float32"
            except Exception:
                try:
                    decoder = BinaryPayloadDecoder.fromRegisters(r["registers"], byteorder=Endian.Big, wordorder=Endian.Little)
                    fv = decoder.decode_32bit_float()
                    r["value"] = fv
                    r["type"] = "float32"
                except Exception:
                    r["value"] = "Not a float"
                    r["type"] = "error"
        return r

# ---------- App ----------
class ModbusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deep Sea Modbus Scanner - Async (Background Loop)")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # load config
        try:
            self.config = load_config()
        except Exception as e:
            logger.warning("load_config failed, using defaults: %s", e)
            self.config = {
                "tcp": {"ip": "127.0.0.1", "port": 502},
                "rtu": {"port": "COM1", "baudrate": 9600, "parity": "N", "stopbits": 1, "serial_mode": "RS485"},
                "slave_id": 1,
                "poll_interval": 5
            }

        if not self._validate_config():
            messagebox.showerror("Config Error", "Invalid config keys")
            self.root.destroy()
            return

        # state
        self.scan_results = []
        self.scanning = False
        self.client = None

        # asyncio loop in background thread
        self.loop = asyncio.new_event_loop()
        self.loop_thread = threading.Thread(target=self._start_loop, daemon=True)
        self.loop_thread.start()

        # vars
        self.protocol_var = tk.StringVar(value=self.config.get("protocol", "tcp"))
        self.com_port_var = tk.StringVar(value=self.config["rtu"].get("port", "COM1"))
        self.baud_rate_var = tk.StringVar(value=str(self.config["rtu"].get("baudrate", 9600)))
        self.slave_id_var = tk.StringVar(value=str(self.config.get("slave_id", 1)))
        self.serial_mode_var = tk.StringVar(value=self.config["rtu"].get("serial_mode", "RS485"))
        self.data_type_var = tk.StringVar(value="uint16")
        # block size for uint16 reads
        self.block_size = tk.IntVar(value=50)  # default block read size for uint16

        # build UI
        self.build_ui()

        # start ping task on loop
        asyncio.run_coroutine_threadsafe(self.ping_ip_task(), self.loop)

    def _start_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _validate_config(self):
        for k in ["tcp", "rtu", "slave_id", "poll_interval"]:
            if k not in self.config:
                logger.error("missing config key: %s", k)
                return False
        return True

    def on_closing(self):
        logger.info("Closing app...")
        # stop scanning
        self.scanning = False
        # cancel tasks and stop loop
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:
            pass
        try:
            if self.client:
                try:
                    self.client.close()
                except Exception:
                    pass
        except Exception:
            pass
        self.root.destroy()
        logger.info("Closed")

    def build_ui(self):
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        right = ttk.Frame(main)
        right.grid(row=0, column=1, sticky="ns")

        main.columnconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(8, weight=1)

        # Title
        tf = ttk.Frame(left)
        tf.grid(row=0, column=0, columnspan=4, pady=(0,10))
        ttk.Label(tf, text="Deep Sea Modbus Scanner - Immediate Update", font=("Segoe UI", 16, "bold")).pack()
        ttk.Label(tf, text="by Senzo Mashaba", font=("Segoe UI", 10, "italic"), foreground="gray").pack()

        # Protocol
        ttk.Label(left, text="Protocol").grid(row=1, column=0, sticky="w", padx=5)
        proto = ttk.Combobox(left, textvariable=self.protocol_var, values=["tcp","rtu"], state="readonly", width=10)
        proto.grid(row=1, column=1, sticky="w", padx=5)
        proto.bind("<<ComboboxSelected>>", lambda e: self._on_protocol_change())

        # TCP
        tcp_frame = ttk.LabelFrame(left, text="TCP Configuration", padding=5)
        tcp_frame.grid(row=2, column=0, columnspan=4, sticky="we", padx=5, pady=5)
        ttk.Label(tcp_frame, text="IP Address").grid(row=0, column=0, sticky="w", padx=5)
        self.ip_entry = ttk.Entry(tcp_frame, width=15); self.ip_entry.insert(0, self.config["tcp"]["ip"]); self.ip_entry.grid(row=0,column=1)
        ttk.Label(tcp_frame, text="Port").grid(row=0, column=2, sticky="w", padx=5)
        self.port_entry = ttk.Entry(tcp_frame, width=8); self.port_entry.insert(0, str(self.config["tcp"].get("port",502))); self.port_entry.grid(row=0,column=3)

        # RTU
        rtu_frame = ttk.LabelFrame(left, text="RTU Configuration", padding=5)
        rtu_frame.grid(row=3, column=0, columnspan=4, sticky="we", padx=5, pady=5)
        ttk.Label(rtu_frame, text="COM Port").grid(row=0, column=0, sticky="w", padx=5)
        self.com_combo = ttk.Combobox(rtu_frame, textvariable=self.com_port_var, values=COM_PORTS, state="readonly", width=8)
        self.com_combo.grid(row=0,column=1)
        ttk.Label(rtu_frame, text="Baud Rate").grid(row=0, column=2, sticky="w", padx=5)
        ttk.Combobox(rtu_frame, textvariable=self.baud_rate_var, values=BAUD_RATES, state="readonly", width=8).grid(row=0,column=3)
        ttk.Label(rtu_frame, text="Slave ID").grid(row=1, column=0, sticky="w", padx=5)
        ttk.Combobox(rtu_frame, textvariable=self.slave_id_var, values=SLAVE_IDS, state="readonly", width=8).grid(row=1,column=1)
        ttk.Label(rtu_frame, text="Serial Mode").grid(row=1, column=2, sticky="w", padx=5)
        ttk.Combobox(rtu_frame, textvariable=self.serial_mode_var, values=SERIAL_MODES, state="readonly", width=8).grid(row=1,column=3)
        ttk.Label(rtu_frame, text="Parity").grid(row=2, column=0, sticky="w", padx=5)
        self.parity_var = tk.StringVar(value=self.config["rtu"].get("parity","N"))
        ttk.Combobox(rtu_frame, textvariable=self.parity_var, values=["N","E","O"], state="readonly", width=5).grid(row=2,column=1)
        ttk.Label(rtu_frame, text="Stop Bits").grid(row=2, column=2, sticky="w", padx=5)
        self.stop_bits_var = tk.StringVar(value=str(self.config["rtu"].get("stopbits",1)))
        ttk.Combobox(rtu_frame, textvariable=self.stop_bits_var, values=[1,1.5,2], state="readonly", width=5).grid(row=2,column=3)

        # Status
        sf = ttk.Frame(left); sf.grid(row=4,column=0,columnspan=4,sticky="we", padx=5, pady=5)
        self.status = ttk.Label(sf, text="Status: Ready", foreground="green"); self.status.grid(row=0,column=0,sticky="w")
        self.ping_label = ttk.Label(sf, text="Ping: Checking...", foreground="gray"); self.ping_label.grid(row=0,column=1,sticky="w", padx=20)
        ttk.Button(sf, text="Refresh COM Ports", command=self.refresh_com_ports).grid(row=0,column=2,padx=5)

        # Scanner
        scan_frame = ttk.LabelFrame(left, text=f"Register Scanner (Max: {MAX_REGISTERS_TO_SCAN})", padding=5)
        scan_frame.grid(row=5,column=0,columnspan=4,sticky="we", padx=5, pady=5)
        ttk.Label(scan_frame, text="Start Register").grid(row=0,column=0,sticky="w", padx=5)
        self.start_entry = ttk.Entry(scan_frame,width=10); self.start_entry.insert(0,"0"); self.start_entry.grid(row=0,column=1)
        ttk.Label(scan_frame, text="End Register").grid(row=0,column=2,sticky="w", padx=5)
        self.end_entry = ttk.Entry(scan_frame,width=10); self.end_entry.insert(0,"100"); self.end_entry.grid(row=0,column=3)
        ttk.Label(scan_frame, text="Read As").grid(row=1,column=0,sticky="w", padx=5)
        ttk.Combobox(scan_frame, textvariable=self.data_type_var, values=["uint16","int32","float32"], state="readonly", width=10).grid(row=1,column=1)
        ttk.Label(scan_frame, text="Block size (uint16)").grid(row=1,column=2,sticky="w", padx=5)
        ttk.Entry(scan_frame, textvariable=self.block_size, width=6).grid(row=1,column=3, sticky="w")

        self.scan_btn = ttk.Button(scan_frame, text="Start Scan", command=self.toggle_scan, width=15); self.scan_btn.grid(row=2,column=2,padx=5,pady=5)

        # Progress and output
        pf = ttk.Frame(left); pf.grid(row=7,column=0,columnspan=4, sticky="we", pady=5)
        self.progress = ttk.Progressbar(pf, mode="determinate"); self.progress.pack(fill="x", padx=5)
        self.progress_label = ttk.Label(pf, text="Ready to scan"); self.progress_label.pack()
        of = ttk.LabelFrame(left, text="Scan Results", padding=5); of.grid(row=8,column=0,columnspan=4, sticky="nsew", padx=5, pady=5)
        self.page_output = tk.Text(of, width=70, height=25); self.page_output.pack(fill="both", expand=True, padx=5, pady=5)

        # Exports
        ef = ttk.LabelFrame(right, text="Export Data", padding=10); ef.pack(pady=20)
        ttk.Button(ef, text="Export CSV", command=self.export_csv, width=15).pack(pady=5, padx=10, fill="x")
        ttk.Button(ef, text="Export XML", command=self.export_xml, width=15).pack(pady=5, padx=10, fill="x")
        ttk.Button(ef, text="Export Excel", command=self.export_excel, width=15).pack(pady=5, padx=10, fill="x")
        ttk.Button(ef, text="Export PDF", command=self.export_pdf, width=15).pack(pady=5, padx=10, fill="x")
        ttk.Button(right, text="Quick Rescan", command=self.quick_rescan, width=15).pack(pady=10, padx=10, fill="x")
        ttk.Label(right, text="by Senzo Mashaba", font=("Segoe UI",8,"italic"), foreground="gray").pack(side="bottom", pady=10)

        self._on_protocol_change()

    def _on_protocol_change(self):
        if self.protocol_var.get() == "tcp":
            self.ip_entry.config(state="normal"); self.port_entry.config(state="normal")
            self.com_combo.config(state="disabled")
        else:
            self.ip_entry.config(state="disabled"); self.port_entry.config(state="disabled")
            self.com_combo.config(state="readonly")

    def update_config_from_ui(self):
        self.config["tcp"]["ip"] = self.ip_entry.get()
        try:
            self.config["tcp"]["port"] = int(self.port_entry.get())
        except Exception:
            pass
        self.config["rtu"]["port"] = self.com_port_var.get()
        try:
            self.config["rtu"]["baudrate"] = int(self.baud_rate_var.get())
        except Exception:
            pass
        self.config["rtu"]["parity"] = self.parity_var.get()
        try:
            self.config["rtu"]["stopbits"] = float(self.stop_bits_var.get())
        except Exception:
            pass
        self.config["rtu"]["serial_mode"] = self.serial_mode_var.get()
        try:
            self.config["slave_id"] = int(self.slave_id_var.get())
        except Exception:
            pass

    def validate_register_range(self, start, end):
        total = end - start + 1
        if total > MAX_REGISTERS_TO_SCAN:
            return False, f"Scan range too large: {total}, max {MAX_REGISTERS_TO_SCAN}"
        if start < 0 or end < 0:
            return False, "Register addresses cannot be negative"
        if start > end:
            return False, "Start must be <= end"
        return True, f"Valid range: {total} registers"

    def toggle_scan(self):
        if not self.scanning:
            self.start_scan()
        else:
            self.stop_scanning()

    def start_scan(self):
        try:
            start = int(self.start_entry.get()); end = int(self.end_entry.get())
            data_type = self.data_type_var.get()
        except Exception:
            self.page_output.insert(tk.END, "❌ Invalid register range format.\n"); return

        ok, msg = self.validate_register_range(start, end)
        if not ok:
            self.page_output.insert(tk.END, f"❌ {msg}\n"); return

        self.update_config_from_ui()
        self.page_output.delete("1.0", tk.END)
        self.scan_results.clear()
        self.scanning = True
        self.scan_btn.config(text="Stop Scan")
        self.status.config(text="Status: Scanning...", foreground="orange")

        # schedule scan coroutine on background loop
        fut = asyncio.run_coroutine_threadsafe(self.scan_registers_task(start, end, data_type), self.loop)
        # store future if needed
        self.current_scan_future = fut

    def stop_scanning(self):
        self.scanning = False
        try:
            if hasattr(self, "current_scan_future") and not self.current_scan_future.done():
                self.current_scan_future.cancel()
        except Exception:
            pass
        self.scan_btn.config(text="Start Scan")
        self.status.config(text="Status: Scan Stopped", foreground="red")
        self.progress_label.config(text="Scan stopped by user")

    def quick_rescan(self):
        if self.scan_results:
            addrs = [r["address"] for r in self.scan_results]
            if addrs:
                s, e = min(addrs), max(addrs)
                self.start_entry.delete(0, tk.END); self.start_entry.insert(0, str(s))
                self.end_entry.delete(0, tk.END); self.end_entry.insert(0, str(e))
                self.start_scan()
                return
        messagebox.showinfo("Quick Rescan", "No previous results to rescan.")

    # ---------- Core scanning task ----------
    async def scan_registers_task(self, start, end, data_type):
        """
        Runs on the background asyncio loop. Uses asyncio.to_thread for blocking calls.
        Strategy:
         - For uint16: use block reads of size self.block_size (faster).
         - For int32/float32: read 2 registers at a time (skip next).
        """
        self.update_config_from_ui()
        slave = int(self.config.get("slave_id", 1))

        # create client via blocking factory
        try:
            client = await asyncio.to_thread(create_modbus_client, self.config)
        except Exception as e:
            logger.exception("create_modbus_client failed")
            self.root.after(0, lambda: self.page_output.insert(tk.END, f"❌ Failed to create client: {e}\n"))
            self.root.after(0, lambda: self.status.config(text="Status: Client Error", foreground="red"))
            self.scanning = False
            self.scan_btn.config(text="Start Scan")
            return

        # attempt connect (blocking)
        try:
            connected = await asyncio.to_thread(client.connect)
        except Exception as e:
            logger.warning("connect raised: %s", e)
            connected = False

        if not connected:
            self.root.after(0, lambda: self.page_output.insert(tk.END, "❌ Connection failed.\n"))
            self.root.after(0, lambda: self.status.config(text="Status: Connection Failed", foreground="red"))
            self.scanning = False
            self.scan_btn.config(text="Start Scan")
            try:
                await asyncio.to_thread(client.close)
            except Exception:
                pass
            return

        self.client = client  # keep reference to close later
        conn_info = f"RTU {self.config['rtu']['port']}" if self.protocol_var.get()=="rtu" else f"IP {self.config['tcp']['ip']}:{self.config['tcp'].get('port',502)}"
        total = end - start + 1
        self.root.after(0, lambda: self.page_output.insert(tk.END, f"🔧 Connection: {conn_info}\n"))
        self.root.after(0, lambda: self.page_output.insert(tk.END, f"📊 Scanning registers {start} - {end} as {data_type}...\n"))
        self.root.after(0, lambda: self.page_output.insert(tk.END, f"📈 Total: {total}\n\n"))
        self.root.after(0, lambda: self.progress.config(maximum=total, value=0))

        successful = 0; failed = 0
        scanned = 0
        addr = start

        try:
            if data_type == "uint16":
                blk = max(1, int(self.block_size.get()))
                while addr <= end and self.scanning:
                    # compute how many to read in this block
                    remain = end - addr + 1
                    to_read = min(blk, remain)
                    # perform blocking block read inside thread
                    try:
                        res = await asyncio.to_thread(RawRegisterReader.read_register, client, addr, to_read, slave)
                    except Exception as e:
                        logger.exception("block read exception")
                        # write each address as error for this block
                        for a in range(addr, addr+to_read):
                            self.scan_results.append({"address": a, "value": f"Error: {type(e).__name__}", "type": "uint16", "status":"error"})
                            self.root.after(0, lambda txt=f"Register {a:6d}: ❌ Read Error\n": self.page_output.insert(tk.END, txt))
                            failed += 1
                            scanned += 1
                        addr += to_read
                        # update progress
                        self.root.after(0, lambda v=min(scanned,total): self.progress.config(value=v))
                        self.root.after(0, lambda txt=f"Scanning... {min(scanned,total)}/{total}": self.progress_label.config(text=txt))
                        await asyncio.sleep(0) 
                        continue

                    # res holds .registers if count>1; adapt to block output
                    if res["type"] == "error":
                        # mark block as errors
                        for a in range(addr, addr+to_read):
                            self.scan_results.append({"address": a, "value": res.get("value"), "type": "uint16", "status":"error"})
                            self.root.after(0, lambda txt=f"Register {a:6d}: ❌ Read Error\n": self.page_output.insert(tk.END, txt))
                            failed += 1
                            scanned += 1
                    else:
                        # result['registers'] is list of ints
                        regs = res.get("registers", [])
                        for i, r in enumerate(regs):
                            a = addr + i
                            self.scan_results.append({"address": a, "value": r, "type":"uint16", "status":"success"})
                            self.root.after(0, lambda txt=f"Register {a:6d}: {r}\n": self.page_output.insert(tk.END, txt))
                            successful += 1
                            scanned += 1

                    addr += to_read
                    # progress update
                    self.root.after(0, lambda v=min(scanned,total): self.progress.config(value=v))
                    self.root.after(0, lambda txt=f"Scanning... {min(scanned,total)}/{total}": self.progress_label.config(text=txt))
                    await asyncio.sleep(0)  # yield to loop

            else:
                # int32 or float32: read two registers per address (skip the next)
                step = 2
                read_fn = RawRegisterReader.read_as_int32 if data_type == "int32" else RawRegisterReader.read_as_float32
                while addr <= end and self.scanning:
                    # ensure addr+1 <= end for 2-register read; if not, mark error and break
                    if addr + 1 > end:
                        # cannot read 2 registers at end; mark last as error
                        self.scan_results.append({"address": addr, "value": "Insufficient registers for 2-register read", "type": data_type, "status":"error"})
                        self.root.after(0, lambda txt=f"Register {addr:6d}: ❌ Insufficient registers for 2-register read\n": self.page_output.insert(tk.END, txt))
                        failed += 1
                        scanned += 1
                        self.root.after(0, lambda v=min(scanned,total): self.progress.config(value=v))
                        self.root.after(0, lambda txt=f"Scanning... {min(scanned,total)}/{total}": self.progress_label.config(text=txt))
                        break

                    try:
                        res = await asyncio.to_thread(read_fn, client, addr, slave)
                    except Exception as e:
                        logger.exception("2-register read exception")
                        res = {"value": f"Error: {e}", "registers": [], "type": "error"}

                    if res.get("type") != "error" and not str(res.get("value","")).startswith("Error"):
                        self.scan_results.append({"address": addr, "value": res["value"], "type": data_type, "status":"success"})
                        self.root.after(0, lambda txt=f"Register {addr:6d}: {res['value']}\n": self.page_output.insert(tk.END, txt))
                        successful += 1
                    else:
                        self.scan_results.append({"address": addr, "value": res.get("value"), "type": data_type, "status":"error"})
                        self.root.after(0, lambda txt=f"Register {addr:6d}: ❌ Read Error\n": self.page_output.insert(tk.END, txt))
                        failed += 1

                    addr += step
                    scanned += step
                    self.root.after(0, lambda v=min(scanned,total): self.progress.config(value=v))
                    self.root.after(0, lambda txt=f"Scanning... {min(scanned,total)}/{total}": self.progress_label.config(text=txt))
                    await asyncio.sleep(0)  # yield

        except asyncio.CancelledError:
            logger.info("scan_registers_task cancelled")
        except Exception:
            logger.exception("Unhandled exception in scan_registers_task")
        finally:
            try:
                await asyncio.to_thread(client.close)
            except Exception:
                pass

            if self.scanning:
                summary = "\n📋 Scan Complete:\n"
                summary += f"✅ Successful reads: {successful}\n"
                summary += f"❌ Failed reads: {failed}\n"
                summary += f"📈 Total registers scanned: {len(self.scan_results)}\n"
                self.root.after(0, lambda: self.page_output.insert(tk.END, summary))
                self.root.after(0, lambda: self.status.config(text="Status: Scan Complete", foreground="green"))
                self.root.after(0, lambda: self.progress_label.config(text="Scan complete"))
            else:
                self.root.after(0, lambda: self.status.config(text="Status: Scan Stopped", foreground="red"))
                self.root.after(0, lambda: self.progress_label.config(text="Scan stopped"))

            self.scan_btn.config(text="Start Scan")
            self.scanning = False
            self.client = None

    # ---------- Ping task ----------
    async def ping_ip_task(self):
        import subprocess
        ip = self.config["tcp"].get("ip", "127.0.0.1")
        while True:
            try:
                if self.protocol_var.get() == "tcp":
                    cmd = ["ping", "-n", "1", ip] if subprocess.os.name == "nt" else ["ping", "-c", "1", ip]
                    try:
                        proc = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True, timeout=5)
                        out = proc.stdout or ""
                        reachable = "TTL=" in out or "ttl=" in out
                        status_text = "Ping: Reachable ✅" if reachable else "Ping: Unreachable ❌"
                        color = "green" if reachable else "red"
                        self.root.after(0, lambda txt=status_text, col=color: self.ping_label.config(text=txt, foreground=col))
                    except Exception:
                        self.root.after(0, lambda: self.ping_label.config(text="Ping: Error ❌", foreground="red"))
                else:
                    self.root.after(0, lambda: self.ping_label.config(text="Serial: RTU Mode", foreground="blue"))
            except Exception:
                logger.exception("ping task exception")
            await asyncio.sleep(5)

    # ---------- COM ports ----------
    def refresh_com_ports(self):
        if list_ports is None:
            messagebox.showinfo("Refresh COM Ports", "pyserial missing; install pyserial to enable COM refresh")
            return
        try:
            ports = [p.device for p in list_ports.comports()]
            if ports:
                self.com_combo.config(values=ports)
                messagebox.showinfo("Refresh COM Ports", "COM ports refreshed")
            else:
                messagebox.showinfo("Refresh COM Ports", "No COM ports found")
        except Exception as e:
            messagebox.showerror("Refresh COM Ports", f"Error listing ports: {e}")
            logger.exception("refresh_com_ports failed")

    # ---------- Exports ----------
    def export_csv(self):
        if not self.scan_results:
            messagebox.showinfo("Export CSV", "No results to export")
            return
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not file:
            return
        try:
            with open(file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Deep Sea Modbus Scanner - Immediate Update"])
                writer.writerow(["by Senzo Mashaba"])
                writer.writerow([])
                writer.writerow(["Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow(["Protocol", self.protocol_var.get()])
                writer.writerow(["Maximum Scan Limit", MAX_REGISTERS_TO_SCAN])
                if self.protocol_var.get()=="rtu":
                    writer.writerow(["COM Port", self.com_port_var.get()])
                    writer.writerow(["Baud Rate", self.baud_rate_var.get()])
                    writer.writerow(["Slave ID", self.slave_id_var.get()])
                else:
                    writer.writerow(["IP Address", self.ip_entry.get()])
                    writer.writerow(["Port", self.port_entry.get()])
                writer.writerow([])
                writer.writerow(["Register","Value","Data Type","Status"])
                for it in self.scan_results:
                    writer.writerow([it["address"], it["value"], it["type"], it["status"]])
            messagebox.showinfo("Export CSV", f"Exported to {file}")
        except Exception:
            logger.exception("CSV export failed")
            messagebox.showerror("Export CSV", "Failed to write CSV")

    def export_xml(self):
        if not self.scan_results:
            messagebox.showinfo("Export XML", "No results to export"); return
        file = filedialog.asksaveasfilename(defaultextension=".xml", filetypes=[("XML","*.xml")])
        if not file: return
        try:
            root = ET.Element("ModbusScan")
            app = ET.SubElement(root, "ApplicationInfo")
            ET.SubElement(app, "Application").text = "Deep Sea Modbus Scanner - Immediate Update"
            ET.SubElement(app, "Author").text = "Senzo Mashaba"
            ET.SubElement(app, "ExportTimestamp").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            meta = ET.SubElement(root, "Metadata")
            ET.SubElement(meta, "Timestamp").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ET.SubElement(meta, "Protocol").text = self.protocol_var.get()
            ET.SubElement(meta, "MaximumScanLimit").text = str(MAX_REGISTERS_TO_SCAN)
            if self.protocol_var.get()=="rtu":
                ET.SubElement(meta, "COMPort").text = self.com_port_var.get()
                ET.SubElement(meta, "BaudRate").text = self.baud_rate_var.get()
                ET.SubElement(meta, "SlaveID").text = self.slave_id_var.get()
            else:
                ET.SubElement(meta, "IPAddress").text = self.ip_entry.get()
                ET.SubElement(meta, "Port").text = self.port_entry.get()
            results = ET.SubElement(root, "Results")
            for it in self.scan_results:
                item = ET.SubElement(results, "Item")
                ET.SubElement(item, "Register").text = str(it["address"])
                ET.SubElement(item, "Value").text = str(it["value"])
                ET.SubElement(item, "DataType").text = it["type"]
                ET.SubElement(item, "Status").text = it["status"]
            tree = ET.ElementTree(root); tree.write(file, encoding="utf-8", xml_declaration=True)
            messagebox.showinfo("Export XML", f"Exported to {file}")
        except Exception:
            logger.exception("XML export failed")
            messagebox.showerror("Export XML", "Failed to write XML")

    def export_excel(self):
        if xlsxwriter is None:
            messagebox.showinfo("Export Excel", "xlsxwriter not installed"); return
        if not self.scan_results:
            messagebox.showinfo("Export Excel", "No results"); return
        file = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel","*.xlsx")])
        if not file: return
        try:
            wb = xlsxwriter.Workbook(file); ws = wb.add_worksheet("Scan Results")
            bold = wb.add_format({"bold": True})
            title = wb.add_format({"bold": True, "font_size": 14})
            auth = wb.add_format({"italic": True, "font_color": "gray"})
            ws.write("A1","Deep Sea Modbus Scanner - Immediate Update", title)
            ws.write("A2","by Senzo Mashaba", auth); ws.write("A3","")
            ws.write("A4","Timestamp", bold); ws.write("B4", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            ws.write("A5","Protocol", bold); ws.write("B5", self.protocol_var.get())
            ws.write("A6","Maximum Scan Limit", bold); ws.write("B6", MAX_REGISTERS_TO_SCAN)
            start_row = 10
            ws.write(f"A{start_row}","Register", bold); ws.write(f"B{start_row}","Value", bold)
            ws.write(f"C{start_row}","Data Type", bold); ws.write(f"D{start_row}","Status", bold)
            row = start_row + 1
            for it in self.scan_results:
                ws.write(row,0,it["address"]); ws.write(row,1,str(it["value"])); ws.write(row,2,it["type"]); ws.write(row,3,it["status"])
                row += 1
            wb.close(); messagebox.showinfo("Export Excel", f"Exported to {file}")
        except Exception:
            logger.exception("Excel export failed"); messagebox.showerror("Export Excel", "Failed to write Excel")

    def export_pdf(self):
        if FPDF is None:
            messagebox.showinfo("Export PDF", "fpdf not installed"); return
        if not self.scan_results:
            messagebox.showinfo("Export PDF", "No results"); return
        file = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF","*.pdf")])
        if not file: return
        try:
            pdf = FPDF(); pdf.set_auto_page_break(auto=True, margin=15); pdf.add_page()
            pdf.set_font("Arial","B",16); pdf.cell(0,10,"Deep Sea Modbus Scanner - Immediate Update", ln=True)
            pdf.set_font("Arial","I",12); pdf.cell(0,8,"by Senzo Mashaba", ln=True); pdf.ln(5)
            pdf.set_font("Arial","",11); pdf.cell(0,8,f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.cell(0,8,f"Protocol: {self.protocol_var.get()}", ln=True); pdf.ln(4)
            pdf.set_font("Arial","B",11); pdf.cell(30,8,"Register", border=1); pdf.cell(60,8,"Value", border=1); pdf.cell(30,8,"Data Type", border=1); pdf.cell(30,8,"Status", border=1, ln=True)
            pdf.set_font("Arial","",11)
            for it in self.scan_results:
                pdf.cell(30,8,str(it["address"]), border=1); pdf.cell(60,8,str(it["value"]), border=1)
                pdf.cell(30,8,it["type"], border=1); pdf.cell(30,8,it["status"], border=1, ln=True)
            pdf.output(file); messagebox.showinfo("Export PDF", f"Exported to {file}")
        except Exception:
            logger.exception("PDF export failed"); messagebox.showerror("Export PDF", "Failed to write PDF")

# ---------- Run ----------
def main():
    root = tk.Tk()
    app = ModbusApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()