import csv
import os
from datetime import datetime

def log_to_csv(filename, data):
    file_exists = os.path.isfile(filename)
    with open(filename, mode='a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Timestamp"] + [label for label, _ in data])
        writer.writerow([datetime.now().isoformat()] + [value for _, value in data])
