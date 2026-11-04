import io
import json
import web_dashboard

# Ensure sample.pcap is loaded into state
web_dashboard.ensure_sample_pcap_exists()
count = web_dashboard.load_pcap_file(web_dashboard.SAMPLE_PCAP_PATH)
print("Loaded packets count:", count)

class MockSocket:
    def __init__(self, request_bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.wfile = io.BytesIO()
    def makefile(self, mode, *args, **kwargs):
        if "r" in mode:
            return self.rfile
        return self.wfile
    def sendall(self, data):
        self.wfile.write(data)

def test_endpoint(path):
    req_bytes = f"GET {path} HTTP/1.1\r\nHost: localhost:5000\r\n\r\n".encode("utf-8")
    sock = MockSocket(req_bytes)
    handler = web_dashboard.DashboardRequestHandler(sock, ("127.0.0.1", 5000), None)
    output = sock.wfile.getvalue()
    lines = output.split(b"\r\n")
    status_line = lines[0].decode("utf-8", errors="replace")
    body = output.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in output else b""
    print(f"Path: {path} -> {status_line} (Body length: {len(body)} bytes)")
    return body

pkts_body = test_endpoint("/api/packets")
stats_body = test_endpoint("/api/stats")
ifaces_body = test_endpoint("/api/interfaces")
html_body = test_endpoint("/")

# Check JSON parsing of packets
data = json.loads(pkts_body.decode("utf-8"))
print("Packets in JSON:", len(data.get("packets", [])))
print("Alerts in JSON:", len(data.get("alerts", [])))
print("Active source:", data.get("active_source"))
