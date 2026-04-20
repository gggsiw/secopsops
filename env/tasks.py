from env.models import Alert, LogEntry


def get_task(name: str) -> dict:
    """
    Returns a task dict with:
      - alerts: List[Alert]
      - logs: List[LogEntry]
      - expected_chain: dict[alert_id -> list of acceptable action sequences]
      - description: str
      - difficulty: str
    """
    if name == "easy":
        return {
            "difficulty": "easy",
            "description": "Straightforward malware and false positive triage. One correct action per alert.",
            "alerts": [
                Alert(
                    id="1", type="malware", severity="high",
                    description="Known C2 beacon from 192.168.1.10 — matches ThreatIntel feed IOC",
                    source_ip="192.168.1.10", destination_ip="45.33.32.100",
                    user="svc_account", timestamp="2024-01-15T08:02:11Z",
                    tags=["c2", "beacon", "threatintel"]
                ),
                Alert(
                    id="2", type="malware", severity="high",
                    description="Ransomware signature STOP/DJVU detected on host 10.0.0.99",
                    source_ip="10.0.0.99", destination_ip="185.220.101.5",
                    user="john.doe", timestamp="2024-01-15T08:05:44Z",
                    tags=["ransomware", "encryption", "stop-djvu"]
                ),
                Alert(
                    id="3", type="false_positive", severity="low",
                    description="Internal Nessus scanner 192.168.1.1 — whitelisted in asset register",
                    source_ip="192.168.1.1", destination_ip="192.168.0.0/24",
                    user="scanner_svc", timestamp="2024-01-15T08:10:00Z",
                    tags=["scanner", "whitelisted", "nessus"]
                ),
            ],
            "logs": [
                LogEntry(timestamp="2024-01-15T08:01:55Z", ip="192.168.1.10", event="dns_lookup", details="Resolved c2-domain.ru"),
                LogEntry(timestamp="2024-01-15T08:02:10Z", ip="192.168.1.10", event="outbound_connection", details="Port 443 to 45.33.32.100"),
                LogEntry(timestamp="2024-01-15T08:05:30Z", ip="10.0.0.99", event="file_rename_bulk", details="3,241 files renamed .djvu in 8s"),
                LogEntry(timestamp="2024-01-15T08:05:44Z", ip="10.0.0.99", event="ransom_note_drop", details="README.txt dropped on Desktop"),
                LogEntry(timestamp="2024-01-15T08:09:50Z", ip="192.168.1.1", event="port_scan", details="Nessus scan schedule #42"),
            ],
            # For each alert: list of accepted action chains (any of these = full score)
            "expected_chain": {
                "1": [["block_ip"], ["block_ip", "report"], ["escalate", "block_ip"]],
                "2": [["block_ip"], ["block_ip", "report"], ["escalate", "block_ip"]],
                "3": [["close"], ["investigate", "close"]],
            },
        }

    elif name == "medium":
        return {
            "difficulty": "medium",
            "description": "Brute-force and credential abuse. Logs must be queried before blocking to earn full score.",
            "alerts": [
                Alert(
                    id="1", type="login", severity="medium",
                    description="15 failed SSH logins in 90 seconds from 10.0.0.5",
                    source_ip="10.0.0.5", user="root",
                    timestamp="2024-01-15T09:01:00Z",
                    tags=["brute-force", "ssh"]
                ),
                Alert(
                    id="2", type="login", severity="medium",
                    description="Successful login after 20 failures — possible credential stuffing from 10.0.0.8",
                    source_ip="10.0.0.8", user="admin",
                    timestamp="2024-01-15T09:04:22Z",
                    tags=["credential-stuffing", "success-after-failure"]
                ),
                Alert(
                    id="3", type="login", severity="low",
                    description="Single failed login from 172.16.0.3 — user confirmed typo via helpdesk",
                    source_ip="172.16.0.3", user="alice",
                    timestamp="2024-01-15T09:06:00Z",
                    tags=["single-failure", "helpdesk-confirmed"]
                ),
                Alert(
                    id="4", type="login", severity="high",
                    description="Login from Tor exit node 45.33.32.156 with valid admin credentials",
                    source_ip="45.33.32.156", user="admin",
                    timestamp="2024-01-15T09:10:05Z",
                    tags=["tor", "admin", "high-risk"]
                ),
            ],
            "logs": [
                LogEntry(timestamp="2024-01-15T09:00:50Z", ip="10.0.0.5", event="login_fail", user="root", details="SSH attempt 1"),
                LogEntry(timestamp="2024-01-15T09:00:52Z", ip="10.0.0.5", event="login_fail", user="root", details="SSH attempt 8"),
                LogEntry(timestamp="2024-01-15T09:01:00Z", ip="10.0.0.5", event="login_fail", user="root", details="SSH attempt 15"),
                LogEntry(timestamp="2024-01-15T09:03:55Z", ip="10.0.0.8", event="login_fail", user="admin", details="Attempt 20"),
                LogEntry(timestamp="2024-01-15T09:04:22Z", ip="10.0.0.8", event="login_success", user="admin", details="Logged in"),
                LogEntry(timestamp="2024-01-15T09:04:30Z", ip="10.0.0.8", event="data_access", user="admin", details="Accessed /etc/shadow"),
                LogEntry(timestamp="2024-01-15T09:10:05Z", ip="45.33.32.156", event="login_success", user="admin", details="Tor exit node confirmed"),
                LogEntry(timestamp="2024-01-15T09:10:15Z", ip="45.33.32.156", event="privilege_escalation", user="admin", details="sudo -i"),
            ],
            "expected_chain": {
                "1": [["query_logs", "block_ip"], ["query_siem", "block_ip"], ["block_ip", "create_ticket"]],
                "2": [["query_logs", "block_ip"], ["query_logs", "escalate"], ["query_siem", "block_ip", "create_ticket"]],
                "3": [["investigate", "close"], ["query_logs", "close"], ["close"]],
                "4": [["escalate"], ["block_ip", "escalate"], ["escalate", "create_ticket"]],
            },
        }

    elif name == "hard":
        return {
            "difficulty": "hard",
            "description": "Full APT kill chain. Phishing → lateral movement → exfiltration. Context from prior steps required for full score.",
            "alerts": [
                Alert(
                    id="1", type="phishing", severity="low",
                    description="User jane.smith clicked link in email from spoofed CFO account — IP 203.0.113.5",
                    source_ip="203.0.113.5", user="jane.smith",
                    timestamp="2024-01-15T10:00:00Z",
                    tags=["phishing", "spearphishing", "initial-access"]
                ),
                Alert(
                    id="2", type="lateral_movement", severity="high",
                    description="Host 192.168.2.15 (jane.smith workstation) scanning internal /16 — post-phishing",
                    source_ip="192.168.2.15", user="jane.smith",
                    timestamp="2024-01-15T10:08:30Z",
                    tags=["lateral-movement", "internal-recon", "post-compromise"]
                ),
                Alert(
                    id="3", type="false_positive", severity="low",
                    description="Automated backup job 192.168.1.200 triggers network scan IDS rule — known schedule",
                    source_ip="192.168.1.200",
                    timestamp="2024-01-15T10:11:00Z",
                    tags=["backup", "whitelisted", "false-positive"]
                ),
                Alert(
                    id="4", type="exfiltration", severity="high",
                    description="2.3 GB outbound to unknown IP 198.51.100.7 over DNS tunneling — active NOW",
                    source_ip="198.51.100.7", destination_ip="198.51.100.7",
                    user="jane.smith", timestamp="2024-01-15T10:15:22Z",
                    tags=["exfiltration", "dns-tunnel", "data-loss"]
                ),
                Alert(
                    id="5", type="login", severity="high",
                    description="Admin login from same external IP 203.0.113.5 (phishing source) — new device, foreign geo",
                    source_ip="203.0.113.5", user="admin",
                    timestamp="2024-01-15T10:18:44Z",
                    tags=["admin-compromise", "foreign-geo", "apt"]
                ),
            ],
            "logs": [
                LogEntry(timestamp="2024-01-15T10:00:00Z", ip="203.0.113.5", event="email_link_click", user="jane.smith", details="Malicious URL: hxxp://cfo-secure[.]ru/invoice.pdf"),
                LogEntry(timestamp="2024-01-15T10:00:45Z", ip="203.0.113.5", event="payload_download", user="jane.smith", details="Meterpreter stager downloaded"),
                LogEntry(timestamp="2024-01-15T10:01:00Z", ip="192.168.2.15", event="c2_beacon", user="jane.smith", details="Beacon interval 60s to 203.0.113.5"),
                LogEntry(timestamp="2024-01-15T10:08:30Z", ip="192.168.2.15", event="internal_port_scan", user="jane.smith", details="SYN scan 192.168.0.0/16 port 445,3389"),
                LogEntry(timestamp="2024-01-15T10:10:55Z", ip="192.168.1.200", event="backup_job_start", details="Scheduled backup #7 — rsync to NAS"),
                LogEntry(timestamp="2024-01-15T10:15:00Z", ip="192.168.2.15", event="dns_tunnel_start", user="jane.smith", details="dnscat2 session to 198.51.100.7"),
                LogEntry(timestamp="2024-01-15T10:15:22Z", ip="198.51.100.7", event="large_upload", details="2.3 GB — /hr/salary_2024.xlsx, /finance/Q4.zip"),
                LogEntry(timestamp="2024-01-15T10:18:44Z", ip="203.0.113.5", event="admin_login", user="admin", details="New device fingerprint, geo=RU"),
                LogEntry(timestamp="2024-01-15T10:18:55Z", ip="203.0.113.5", event="privilege_escalation", user="admin", details="Added to Domain Admins group"),
            ],
            "expected_chain": {
                "1": [["query_logs", "report"], ["investigate", "report"], ["query_siem", "report", "create_ticket"]],
                "2": [["escalate", "block_ip"], ["block_ip", "escalate"], ["escalate", "create_ticket", "block_ip"]],
                "3": [["close"], ["investigate", "close"]],
                "4": [["block_ip"], ["block_ip", "escalate"], ["block_ip", "create_ticket", "escalate"]],
                "5": [["escalate", "block_ip"], ["block_ip", "escalate", "create_ticket"]],
            },
        }

    else:
        raise ValueError(f"Unknown task '{name}'. Choose: easy, medium, hard")
