from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
import subprocess
import pandas as pd
import os
import json

app = Flask(__name__)
CORS(app)  # Allow requests from the frontend

# Specify the network interface for capturing traffic
INTERFACE = r"\Device\NPF_{F0B0FF62-5C09-4A7F-80B9-8CD0D464FBA6}"  # Fifth interface (Wi-Fi)

# Function to capture network traffic and save features to a CSV
def capture_network_traffic(csv_filename='network_traffic.csv', duration=60):
    try:
        print("Starting network traffic capture...")

        # Ensure tshark is installed
        if subprocess.run(["tshark", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
            return False, "Error: TShark is not installed or not in PATH."

        # Define tshark fields to capture
        tshark_fields = [
            '-e', 'ip.src',  # Source IP
            '-e', 'ip.dst',  # Destination IP
            '-e', 'tcp.srcport',  # TCP Source Port
            '-e', 'tcp.dstport',  # TCP Destination Port
            '-e', 'udp.srcport',  # UDP Source Port
            '-e', 'udp.dstport',  # UDP Destination Port
            '-e', 'frame.len',  # Packet Length
            '-e', 'frame.time_epoch',  # Timestamp
            '-e', 'frame.protocols',  # Protocols
            '-e', 'tcp.flags',  # TCP Flags
            '-e', 'udp.length',  # UDP Length
        ]

        # Command to capture traffic from the specified interface
        tshark_cmd = ["tshark", "-i", INTERFACE, "-a", f"duration:{duration}", "-T", "fields"] + tshark_fields + ["-E", "separator=,", "-E", "header=y"]

        # Run tshark and capture output
        print(f"Running TShark command on interface: {INTERFACE}")
        result = subprocess.run(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Parse tshark output into DataFrame
        raw_data = result.stdout
        if not raw_data.strip():
            return False, "Error: No packets captured. Ensure the selected network interface is active."

        with open("raw_traffic.csv", "w") as file:
            file.write(raw_data)

        df_raw = pd.read_csv("raw_traffic.csv")

        # Process raw traffic data to calculate flow-level features
        print("Processing raw traffic data...")
        df_raw['timestamp'] = pd.to_datetime(df_raw['frame.time_epoch'], unit='s')
        df_raw['protocols'] = df_raw['frame.protocols'].str.split(':').str[-1]  # Get the last protocol
        df_raw['length'] = pd.to_numeric(df_raw['frame.len'], errors='coerce')

        # Aggregate metrics
        grouped = df_raw.groupby(['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport']).agg({
            'timestamp': ['min', 'max'],  # First and last packet times
            'length': ['sum', 'mean', 'std', 'count'],  # Metrics for packet lengths
        }).reset_index()

        # Flatten multi-level columns
        grouped.columns = [' '.join(col).strip() for col in grouped.columns.values]
        grouped.rename(columns={
            'timestamp min': 'flow_start_time',
            'timestamp max': 'flow_end_time',
            'length sum': 'total_bytes',
            'length mean': 'avg_packet_size',
            'length std': 'packet_size_stddev',
            'length count': 'packet_count'
        }, inplace=True)

        # Calculate additional flow metrics
        grouped['flow_duration'] = (grouped['flow_end_time'] - grouped['flow_start_time']).dt.total_seconds()
        grouped['bytes_per_second'] = grouped['total_bytes'] / grouped['flow_duration'].replace(0, 1)
        grouped['packets_per_second'] = grouped['packet_count'] / grouped['flow_duration'].replace(0, 1)

        # Save processed and aggregated features to CSV
        grouped.to_csv(csv_filename, index=False)
        print(f"Aggregated traffic features saved to {csv_filename}")
        return True, f"Network traffic captured and saved to {csv_filename}."

    except subprocess.CalledProcessError as e:
        return False, f"Error while running TShark: {e}"
    except Exception as e:
        return False, f"An unexpected error occurred: {e}"


@app.route('/capture-traffic', methods=['POST'])
def capture_traffic():
    if not request.is_json:  # Check if Content-Type is JSON
        return jsonify({'message': 'Invalid Content-Type. Expected application/json.'}), 415

    # Call the capture network function
    success, message = capture_network_traffic()
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'message': 'Failed to capture network traffic.'}), 500


if __name__ == '__main__':
    # Run the Flask app
    app.run(debug=True, port=5000)
