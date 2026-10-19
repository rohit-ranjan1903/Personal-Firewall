??? Python Windows Firewall
A lightweight, rule-based packet-filtering firewall built with Python and WinDivert. It monitors network traffic on Windows and allows or blocks packets according to custom rules defined in rules.json.
Designed as an educational cybersecurity project, it demonstrates packet inspection, firewall rule evaluation, traffic filtering, and network logging.

?? Table of Contents
* Overview
* Features
* How It Works
* Technologies Used
* Project Structure
* Requirements
* Installation
* Usage
* Firewall Rules
* Testing
* Logging and Monitoring
* Limitations

?? Overview
This project implements a custom firewall that inspects network packets entering and leaving a Windows machine.
Instead of relying entirely on predefined firewall rules, you can create your own filtering rules in a JSON configuration file.
For every intercepted packet, the firewall:
1. Identifies the packet's direction and network details.
2. Determines its protocol, IP addresses, and available port information.
3. Evaluates configured rules in order.
4. Applies the action specified by the first matching rule.
5. Logs blocked traffic for analysis.
If no rule matches, the firewall applies the configured default_action.
Tip: Start in monitor mode before enforcing rules. Incorrect filtering rules can interrupt internet access or other network connections.

? Features
FeatureDescription?? Inbound FilteringFilter incoming network traffic?? Outbound FilteringFilter outgoing network traffic?? Protocol FilteringMatch TCP, UDP, ICMP, or any protocol?? IP FilteringMatch individual IP addresses and CIDR ranges?? Port FilteringFilter traffic using local and remote ports?? Custom RulesConfigure filtering behavior using rules.json?? Monitor ModeObserve potential blocking decisions without dropping packets?? Traffic LoggingRecord blocked packets in firewall.log?? Traffic SummaryDisplay per-protocol statistics when the program exits?? Verbose ModeDisplay additional information, including allowed packets
?? How It Works
The firewall uses WinDivert, accessed through the Python pydivert library, to intercept network packets and process them in user space.
flowchart TD
    A[Network Traffic] --> B[WinDivert]
    B --> C[Python Firewall]
    C --> D[Extract Packet Details]
    D --> E[Evaluate rules.json]
    E --> F{Rule Matches?}
    F -->|Yes| G{Action}
    F -->|No| H[Default Action]
    G -->|ALLOW| I[Re-inject Packet]
    G -->|BLOCK| J[Drop Packet]
    H --> I
    H --> J
    J --> K[Write to firewall.log]
Packet-processing workflow
1. Packet interception: WinDivert diverts matching packets from the Windows networking stack.
2. Packet inspection: The Python program extracts available information, including direction, protocol, addresses, and ports.
3. Rule evaluation: Rules are checked from top to bottom.
4. Decision: The first matching rule determines whether the packet is allowed or blocked.
5. Packet handling: Allowed packets are reinjected into the network stack, while blocked packets are dropped.
6. Logging: Blocked packets are recorded for later inspection.
Rule priority
The first matching rule wins. Therefore, more specific rules should generally appear before broader rules.
If no rule matches, the firewall uses default_action.

?? Technologies Used
* Python — Core firewall logic and rule engine
* WinDivert — Windows packet interception and reinjection
* pydivert — Python interface to WinDivert
* JSON — Firewall rule configuration
* Logging — Recording blocked traffic and debugging information

?? Project Structure
python-windows-firewall/
?
??? firewall.py          # Main firewall engine
??? rules.json           # Firewall rules and default action
??? requirements.txt     # Python dependencies
??? firewall.log         # Generated firewall log
??? README.md            # Project documentation
The structure above represents the expected layout; adjust filenames if your implementation differs.

?? Requirements
Before running the firewall, make sure you have:
* Windows 10 or Windows 11
* Python 3 installed
* Administrator privileges
* WinDivert-compatible dependencies
* An internet connection for installing packages, if needed

?? Installation
1. Clone the repository
Replace YOUR_USERNAME with your GitHub username and YOUR_REPOSITORY with your repository name.
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
2. Open the project directory
cd YOUR_REPOSITORY
3. Install dependencies
python -m pip install -r requirements.txt
4. Run Command Prompt or PowerShell as Administrator
Administrator privileges are generally required for WinDivert packet interception.
Before enforcing rules, verify that rules.json exists and contains valid configuration.

?? Usage
Run the following commands from an elevated Command Prompt or PowerShell in the project directory.
Monitor mode — recommended first
python firewall.py --monitor
Monitor mode is intended to report what the firewall would block without actually dropping packets. Confirm that your implementation supports this behavior before relying on it.
Enforce firewall rules
python firewall.py
Starts packet filtering and applies the configured allow/block decisions.
Verbose mode
python firewall.py --verbose
Displays additional packet information, including allowed traffic, if supported by the implementation.
Stop the firewall
Press Ctrl+C to request a graceful shutdown.
The program should clean up its WinDivert handle and report its traffic summary. If interception is closed correctly, normal packet handling can resume, but active connections may still be disrupted.

?? Firewall Rules
Firewall behavior is controlled by rules.json.
Example: Block incoming Telnet traffic
{
  "name": "Block incoming Telnet",
  "action": "block",
  "direction": "in",
  "protocol": "tcp",
  "local_port": 23
}
This rule matches incoming TCP packets addressed to local port 23 and blocks them when enforcement is enabled.
Rule fields
FieldAccepted valuesPurposenameStringIdentifies the ruleactionallow, blockDecision when the rule matchesdirectionin, out, anyTraffic directionprotocoltcp, udp, icmp, anyNetwork protocolremote_ipIP, CIDR, or listMatches remote IP addresses or networksremote_portNumber or listMatches remote port numberslocal_portNumber or listMatches local port numbersThe supported values above describe the intended configuration format. Confirm the parser's actual behavior before relying on optional fields or combinations.
Example: Block an outgoing IP address
{
  "name": "Block example destination",
  "action": "block",
  "direction": "out",
  "remote_ip": "93.184.216.34"
}
This rule blocks matching outgoing packets to the specified remote IP, subject to the firewall's packet matching and default-action logic.
Example: Block a range of IP addresses
{
  "name": "Block example network",
  "action": "block",
  "direction": "out",
  "remote_ip": "192.0.2.0/24"
}
CIDR notation allows you to match an IP network rather than a single address.
Important: The examples above are individual rule objects. If your implementation expects a JSON array, place the rules inside an array and configure default_action in the format expected by your rule loader.
Understanding default_action
The default action applies when no configured rule matches a packet.
* allow — permit unmatched packets.
* block — drop unmatched packets.
A default-block policy can interrupt internet access and essential services if the necessary allow rules are missing. Test carefully before enabling it.

?? Testing
Test the firewall in a controlled environment before using enforcement mode.
Test 1: Verify a destination IP
Use DNS lookup to obtain an IP address:
nslookup example.com
Add a rule for a destination IP returned by the lookup, then attempt to access the destination.
Keep in mind that websites may use multiple IP addresses, CDNs, or encrypted connections. Blocking one IP does not necessarily block the entire website.
Test 2: Block outgoing ICMP traffic
Add an outgoing ICMP block rule in the format supported by your configuration parser.
Then run:
ping 8.8.8.8
Compare the result with the firewall running in monitor mode and enforcement mode.
Note that a failed ping does not, by itself, prove that the firewall blocked the packet. The destination or network may also block ICMP.
Test 3: Inspect the log
After generating test traffic, inspect the log:
type firewall.log
Look for the rule name, packet details, and block decision, depending on what your logger records.
Testing checklist
* Confirm monitor mode does not drop packets.
* Test an inbound filtering rule.
* Test an outbound filtering rule.
* Test TCP and UDP rules.
* Test ICMP filtering.
* Test an IP/CIDR match.
* Verify rule ordering.
* Verify the default action.
* Confirm logs and exit statistics.
* Confirm normal network operation after shutdown.

?? Logging and Monitoring
The firewall writes blocked traffic to:
firewall.log
The log can help you investigate:
* Blocked connection attempts
* Unexpected outbound traffic
* Protocol usage
* Rule-matching behavior
* Potentially suspicious network activity
Verbose mode can provide additional visibility into allowed packets.
Note: This is packet-level logging, not a complete security monitoring system. A blocked packet is not necessarily malicious, and a permitted packet is not necessarily safe.

?? Limitations and Future Improvements
The current design is intended as a learning project and has several limitations.
* Stateless filtering: Rules evaluate packets individually rather than maintaining a complete connection-tracking table.
* No graphical interface: Configuration is managed through JSON files.
* Manual rule reload: Changes may require restarting the program.
* IPv6 testing: IPv6 support requires additional validation across different packet types and rules.
* Limited application awareness: Filtering is primarily based on packet attributes, not application identity or full payload inspection.
* Operational resilience: Additional error handling, recovery logic, and shutdown testing may be needed.
* Performance testing: High-volume traffic may require optimization and benchmarking.
* Security validation: Rule parsing, malformed configuration handling, and edge cases require testing.
Planned improvements
* Connection tracking and stateful filtering
* Live rule reloading
* Graphical user interface
* Improved IPv6 test coverage
* More detailed traffic statistics
* Rule validation and configuration error reporting
* Automated unit and integration tests
* Performance benchmarking
????? Contributing
Contributions, bug reports, and suggestions are welcome.
1. Fork the repository.
2. Create a feature branch.
3. Make and test your changes.
4. Submit a pull request describing the improvement.
Please include reproducible steps when reporting bugs.



