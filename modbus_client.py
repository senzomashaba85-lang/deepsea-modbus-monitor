from pymodbus.client.sync import ModbusTcpClient, ModbusSerialClient
import yaml

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def create_modbus_client(config):
    if config["protocol"] == "tcp":
        return ModbusTcpClient(
            host=config["tcp"]["ip"],
            port=config["tcp"]["port"],
            timeout=3
        )
    elif config["protocol"] == "rtu":
        return ModbusSerialClient(
            method="rtu",
            port=config["rtu"]["port"],
            baudrate=config["rtu"]["baudrate"],
            parity=config["rtu"]["parity"],
            stopbits=config["rtu"]["stopbits"],
            bytesize=config["rtu"]["bytesize"],
            timeout=config["rtu"]["timeout"]
        )
    else:
        raise ValueError("Unsupported protocol")
