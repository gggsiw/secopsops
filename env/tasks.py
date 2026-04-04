from env.models import Alert, LogEntry

def get_task(name):
    if name == "easy":
        return {
            "alerts": [
                Alert(id="1", type="malware", severity="high", description="Known malicious IP 192.168.1.10 sending C2 beacons", source_ip="192.168.1.10"),
                Alert(id="2", type="malware", severity="high", description="Ransomware signature detected from 10.0.0.99", source_ip="10.0.0.99"),
                Alert(id="3", type="false_positive", severity="low", description="Internal scanner 192.168.1.1 flagged by IDS — known safe device", source_ip="192.168.1.1"),
            ],
            "logs": [],
        }
    elif name == "medium":
        return {
            "alerts": [
                Alert(id="1", type="login", severity="medium", description="15 failed logins in 2 minutes from 10.0.0.5", source_ip="10.0.0.5"),
                Alert(id="2", type="login", severity="medium", description="Successful login after 20 failures from 10.0.0.8", source_ip="10.0.0.8"),
                Alert(id="3", type="login", severity="low", description="Single failed login from 172.16.0.3 — likely typo", source_ip="172.16.0.3"),
                Alert(id="4", type="login", severity="high", description="Login from blacklisted IP 45.33.32.156 with valid credentials", source_ip="45.33.32.156"),
            ],
            "logs": [
                LogEntry(timestamp="1", ip="10.0.0.5", event="login_fail"),
                LogEntry(timestamp="2", ip="10.0.0.5", event="login_fail"),
                LogEntry(timestamp="3", ip="10.0.0.8", event="login_success"),
                LogEntry(timestamp="4", ip="45.33.32.156", event="login_success"),
                LogEntry(timestamp="5", ip="45.33.32.156", event="data_access"),
            ],
        }
    elif name == "hard":
        return {
            "alerts": [
                Alert(id="1", type="phishing", severity="low", description="User clicked suspicious link from external email — IP 203.0.113.5", source_ip="203.0.113.5"),
                Alert(id="2", type="lateral_movement", severity="high", description="Internal host 192.168.2.15 scanning other internal IPs after phishing", source_ip="192.168.2.15"),
                Alert(id="3", type="false_positive", severity="low", description="Automated backup job from 192.168.1.200 — triggers network scan signature", source_ip="192.168.1.200"),
                Alert(id="4", type="exfiltration", severity="high", description="Large outbound transfer 2.3GB to unknown external IP 198.51.100.7", source_ip="198.51.100.7"),
                Alert(id="5", type="login", severity="high", description="Admin account login from new device in foreign country — IP 203.0.113.5", source_ip="203.0.113.5"),
            ],
            "logs": [
                LogEntry(timestamp="1", ip="203.0.113.5", event="email_link_click"),
                LogEntry(timestamp="2", ip="192.168.2.15", event="internal_port_scan"),
                LogEntry(timestamp="3", ip="192.168.1.200", event="backup_job_start"),
                LogEntry(timestamp="4", ip="198.51.100.7", event="large_upload"),
                LogEntry(timestamp="5", ip="203.0.113.5", event="admin_login"),
                LogEntry(timestamp="6", ip="203.0.113.5", event="privilege_escalation"),
            ],
        }
    else:
        raise ValueError(f"Invalid task: {name}. Choose: easy, medium, hard")
