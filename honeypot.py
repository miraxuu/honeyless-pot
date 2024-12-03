import tkinter as tk
from tkinter import filedialog, scrolledtext
import http.server
import socketserver
import threading
import time
import os
import random
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.all import sniff, Raw, send

#import joblib
#sql_injection_model = joblib.load('sql_injection_model.pkl')

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        file_path = self.server.file_path
        if os.path.isfile(file_path):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "File Not Found")

    def log_request(self, code='-', size='-'):
        request_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        request_line = self.requestline
        headers = self.headers
        host = headers.get("Host", "-")
        user_agent = headers.get("User-Agent", "-")

        if hasattr(self.server, 'log_file'):
            with open(self.server.log_file, 'a') as f:
                f.write("HTTP SERVER LOG\n")
                f.write(f"Time: {request_time}\n")
                f.write(f"Source IP: {client_ip}, Source Port: {client_port}\n")
                f.write(f"Request: {request_line}\n")
                f.write(f"Response Code: {code}, Response Size: {size} bytes\n")
                f.write(f"Host: {host}\n")
                f.write(f"User-Agent: {user_agent}\n")
                f.write("-" * 50 + "\n")

        if hasattr(self.server, 'log_function') and callable(self.server.log_function):
            self.server.log_function(f"Time: {request_time}", "red")
            self.server.log_function(f"Source IP: {client_ip}, Source Port: {client_port}", "red")
            self.server.log_function(f"Request: {request_line}", "red")
            self.server.log_function(f"Response Code: {code}, Response Size: {size} bytes", "red")
            self.server.log_function(f"Host: {host}", "red")
            self.server.log_function(f"User-Agent: {user_agent}", "red")
            self.server.log_function("-" * 50, "red")
            
    # if GET request
    '''    if "GET" in request_line:
            #Write to an intermediate log file for processing
            intermediate_log = "intermediate_log.txt"
            with open(intermediate_log, 'w') as f:
                 f.write("HTTP SERVER LOG\n")
                 f.write(f"Time: {request_time}\n")
                 f.write(f"Source IP: {client_ip}\n")
                 f.write(f"Request: {request_line}\n")
                 f.write("-" * 50 + "\n")
    

        #Convert the log and add features
        intermediate_csv = "intermediate_http.csv"
        enriched_csv = "enriched_http.csv"
        process_log_file(intermediate_log, intermediate_csv)
        filter_and_add_features(intermediate_csv, enriched_csv)

        #Load the data and predict
        enriched_data = pd.read_csv(enriched_csv)
        predictions = sql_injection_model.predict(enriched_data)

        #Display the prediction result
        result = predictions[0]
        classification = f"Is this an SQL attack: {result}"
        self.server.log_function(classification, "blue")

        if result == 1:
             #Code to send to an alert to email
    '''

class HoneypotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Honeyless Pot")
        self.ip_var = tk.StringVar(value="0.0.0.0")
        self.port_var = tk.StringVar(value="8081")
        self.file_path = "default_page.html"
        self.server_thread = None
        self.sniffer_thread = None
        self.httpd = None

        self.create_widgets()

    def create_widgets(self):
        #IP Address and Port Entry
        tk.Label(self.root, text="IP ADDRESS").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(self.root, textvariable=self.ip_var).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(self.root, text="PORT").grid(row=0, column=2, padx=5, pady=5)
        tk.Entry(self.root, textvariable=self.port_var).grid(row=0, column=3, padx=5, pady=5)

        #Control Buttons
        self.start_button = tk.Button(self.root, text="Start", command=self.start_server)
        self.start_button.grid(row=1, column=0, padx=5, pady=5)
        self.stop_button = tk.Button(self.root, text="Stop", command=self.stop_server, state="disabled")
        self.stop_button.grid(row=1, column=1, padx=5, pady=5)
        self.config_button = tk.Button(self.root, text="Config", command=self.config_file)
        self.config_button.grid(row=1, column=2, padx=5, pady=5)
        self.reset_button = tk.Button(self.root, text="Reset", command=self.reset_settings)
        self.reset_button.grid(row=1, column=3, padx=5, pady=5)

        #Log Display
        self.log_display = scrolledtext.ScrolledText(self.root, width=70, height=20, state="normal")
        self.log_display.grid(row=2, column=0, columnspan=4, padx=10, pady=10)
        self.log_display.tag_config("red", foreground="red")
        self.log_display.tag_config("blue", foreground="blue")

    def start_server(self):
        ip = self.ip_var.get()
        port = int(self.port_var.get())
        timestamp = time.strftime("%H%M%d%m")
        self.log_file = f"log_file_{timestamp}.txt"

        #Start HTTP server and sniffer
        self.server_thread = threading.Thread(target=self.run_server, args=(ip, port))
        self.server_thread.daemon = True
        self.server_thread.start()

        self.sniffer_thread = threading.Thread(target=self.run_packet_sniffer, args=(ip, port))
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        self.start_button["state"] = "disabled"
        self.stop_button["state"] = "normal"
        self.log(f"Server started on {ip}:{port}", "red")

    def run_server(self, ip, port):
        handler = CustomHTTPRequestHandler
        socketserver.TCPServer.allow_reuse_address = True
        self.httpd = socketserver.TCPServer((ip, port), handler)
        self.httpd.log_function = self.log
        self.httpd.log_file = self.log_file
        self.httpd.file_path = self.file_path
        self.httpd.serve_forever()

    def run_packet_sniffer(self, ip, port):
        def packet_callback(packet):
            features = self.extract_packet_features(packet)
            self.log_packet_to_file(features)

            if UDP in packet:
                udp_layer = packet[UDP]
                src_ip = packet[IP].src
                src_port = udp_layer.sport
                dst_ip = packet[IP].dst
                dst_port = udp_layer.dport

                #Randomized payload for UDP response
                responses = ["Service is running", "Data received", "Processing request"]
                payload = random.choice(responses)

                #Send the UDP response
                self.send_udp_response(src_ip, src_port, dst_ip, dst_port, payload=payload)

        sniff(filter=f"host {ip} and (tcp port {port} or udp port {port})", prn=packet_callback, store=0)

    def send_udp_response(self, src_ip, src_port, dst_ip, dst_port, payload="Honeypot Response"):

        pkt = IP(src=dst_ip, dst=src_ip) / UDP(sport=dst_port, dport=src_port) / payload
        send(pkt, verbose=False)
        self.log(f"Sent UDP response to {src_ip}:{src_port} with payload: {payload}", "blue")

    def extract_packet_features(self, packet):
        features = {}

        features['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

        if Ether in packet:
            features['src_mac'] = packet[Ether].src
            features['dst_mac'] = packet[Ether].dst
            features['eth_type'] = packet[Ether].type

        if IP in packet:
            ip_layer = packet[IP]
            features['src_ip'] = ip_layer.src
            features['dst_ip'] = ip_layer.dst
            features['ttl'] = ip_layer.ttl
            features['ip_proto'] = ip_layer.proto
            features['tos'] = ip_layer.tos
            features['ip_flags'] = ip_layer.flags
            features['frag_offset'] = ip_layer.frag

        if TCP in packet:
            tcp_layer = packet[TCP]
            features['type'] = "TCP"
            features['src_port'] = tcp_layer.sport
            features['dst_port'] = tcp_layer.dport
            features['tcp_flags'] = tcp_layer.sprintf('%TCP.flags%')
            features['seq'] = tcp_layer.seq
            features['ack'] = tcp_layer.ack
            features['window_size'] = tcp_layer.window
            features['urgent_pointer'] = tcp_layer.urgptr
            features['tcp_options'] = tcp_layer.options

        if UDP in packet:
            udp_layer = packet[UDP]
            features['type'] = "UDP"
            features['src_port'] = udp_layer.sport
            features['dst_port'] = udp_layer.dport
            features['udp_len'] = udp_layer.len
            features['udp_checksum'] = udp_layer.chksum

        if Raw in packet:
            raw_data = bytes(packet[Raw])
            try:
                decoded_payload = raw_data.decode('utf-8', errors='replace')
                features['payload_decoded'] = decoded_payload
            except UnicodeDecodeError:
                features['payload_decoded'] = raw_data.hex()
            features['payload_raw'] = raw_data.hex()

        features['packet_size'] = len(packet)

        return features

    def log_packet_to_file(self, features):
        with open(self.log_file, 'a') as f:
            f.write("PACKET FEATURES:\n")
            for key, value in features.items():
                f.write(f"{key}: {value}\n")
            f.write("-" * 50 + "\n")

    def stop_server(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None

        self.start_button["state"] = "normal"
        self.stop_button["state"] = "disabled"
        self.log("Server stopped", "red")

    def reset_settings(self):
        self.ip_var.set("0.0.0.0")
        self.port_var.set("8081")
        self.file_path = "default_page.html"
        self.log_display.delete('1.0', tk.END)
        self.log("Settings reset to default.", "red")

    def config_file(self):
        file = filedialog.askopenfilename(filetypes=[("HTML files", "*.html")])
        self.file_path = file if file else "default_page.html"
        self.log(f"Configured HTML file: {self.file_path}", "red")

    def log(self, message, tag="red"):
        self.log_display.insert(tk.END, f"{message}\n", tag)
        self.log_display.yview(tk.END)
        if hasattr(self, 'log_file') and self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"{message}\n")


#Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = HoneypotGUI(root)
    root.mainloop()
