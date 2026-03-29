"""
Author: Shayne Atkins
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import sys
import threading
import sqlite3
import os
import platform
import datetime
from fileinput import close

print("Python Version:", platform.python_version())
print("Operating System:", os.name)


# A dictionary that maps port numbers to service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter provides controlled access to self.__target, allowing validation or logic
    # (like preventing empty values) when setting it. This helps protect the internal state of the object and makes the
    # code more robust. It also allows the implementation to change later without affecting how other parts of the code
    # access target.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# The PortScanner class reuses code from NetworkTool through inheritance by calling super().__init__(target), which
# initializes the target attribute using the parent class’s logic. This allows PortScanner to use the existing property
# methods for accessing and validating target without rewriting them. For example, when self.target is used in
# scan_port, it relies on the getter defined in NetworkTool.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = None
        # Q4: What would happen without try-except here?
        # If you removed all try-except blocks, any network error (like an unreachable host) would raise an unhandled
        # exception. This could crash the entire program or terminate the thread running the scan. As a result, the
        # scan would stop prematurely, and you wouldn’t get complete results.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service = common_ports.get(port, "Unknown")

            with self.lock:
                self.scan_results.append((port, status, service))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # We use threading so multiple ports can be scanned at the same time, which significantly speeds up the process
    # since each network connection can take time to respond. Without threads, the scanner would check ports one by
    # one (sequentially), waiting for each attempt to finish or time out before moving on. Scanning 1024 ports this
    # way could take a very long time—potentially minutes—especially with a 1-second timeout per port.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()


def save_results(self, results):
    try:
        conn = sqlite3.connect('scan_history.db')
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        ''')

        for port, status, service in results:
            cursor.execute('''
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database Error: {e}")


def load_past_scans():
    conn = sqlite3.connect("scan_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT target, port, status, service, scan_date FROM scans
    """)
    rows = cursor.fetchall()

    if not rows:
        print("No past scans found.")
    else:
        for target, port, status, service, scan_date in rows:
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

    conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":

    try:
        target = input("Enter an IP address (Default: 127.0.0.1): ")
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if not(1 <= start_port <= 1024) or not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port")
        else:
            scanner = PortScanner(target)

            print(f"\nScanning {target} from port {start_port} to {end_port}...")

            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()

            print(f"\n--- Scan Results for {target} ---")
            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")

            print("------")
            print(f"Total open ports found: {len(open_ports)}")

            save_results(target, scanner.scan_results)

            past = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
            if past == "yes":
                load_past_scans()
    except ValueError:
        print("Invalid input. Please enter a valid integer.")

# Q5: New Feature Proposal
# One useful feature would be filtering scan results by specific services (e.g., only showing HTTP or SSH ports). This
# could be implemented with a list comprehension that selects results where the service field matches a desired value,
# such as [r for r in self.scan_results if r[2] == "HTTP"]. This makes it easy for users to quickly focus on relevant
# open ports without manually reviewing all results.
# Diagram: See diagram_101572148.png in the repository root for a flowchart of this proposed feature
