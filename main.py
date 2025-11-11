
import time
from modbus_client import load_config, create_modbus_client
from logger import log_to_csv

REGISTER_LIST = [
    {"address": 772, "label": "Control Mode", "type": "holding"},
    {"address": 48661, "label": "Gen Available LED", "type": "holding"},
    {"address": 48659, "label": "Breaker LED", "type": "holding"},
]

def read_registers(client, slave_id, register_list):
    results = []
    for reg in register_list:
        try:
            if reg["type"] == "input":
                result = client.read_input_registers(reg["address"], 1, unit=slave_id)
            else:
                result = client.read_holding_registers(reg["address"], 1, unit=slave_id)
            value = result.registers[0] if not result.isError() else "Error"
        except Exception as e:
            value = f"Error: {e}"
        print(f"{reg['label']} ({reg['address']}): {value}")
        results.append((reg["label"], value))
    return results

def main():
    config = load_config()
    client = create_modbus_client(config)
    print(f"🔌 Attempting connection to {config['tcp']['ip']}:{config['tcp']['port']}...")
    if not client.connect():
        print(f"❌ Connection failed to {config['tcp']['ip']}:{config['tcp']['port']}")
        return

    print(f"✅ Connected via {config['protocol'].upper()}")
    try:
        while True:
            print("\n📡 Reading registers...")
            results = read_registers(client, config["slave_id"], REGISTER_LIST)
            if config.get("log_csv"):
                log_to_csv(config["csv_file"], results)
            time.sleep(config["poll_interval"])
    except KeyboardInterrupt:
        print("🛑 Stopped by user.")
    finally:
        client.close()

if __name__ == "__main__":
    main()
