import os

def read_config(filepath):
    if os.path.exists(filepath):  # Check
        with open(filepath, 'r') as f:  # Use
            return f.read()

config_data = read_config("/tmp/config.txt")