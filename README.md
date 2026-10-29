Linux SSH Log Analyzer

A Bash-based cybersecurity project that analyzes Linux authentication logs to identify suspicious SSH login activity, repeated failed login attempts, targeted usernames, and basic system security events.

Features

- Automatically detects "/var/log/auth.log" or "/var/log/secure"
- Counts failed and successful SSH login entries
- Identifies top source IPv4 addresses associated with failed logins
- Lists frequently targeted usernames, including invalid users
- Summarizes failed password entries by hour
- Counts failed root login entries
- Reports basic sudo activity and authentication failures
- Identifies potential service errors using log keywords
- Generates alerts when an IPv4 address reaches a configurable threshold
- Exports reports to a text file
- Supports reading log data from standard input

Requirements

- Linux operating system
- Bash 4 or later
- Standard command-line utilities such as "awk", "grep", "sed", "sort", and "uniq"

Installation

Clone the repository:

git clone YOUR_GITHUB_REPOSITORY_URL
cd log-analyzer

Make the script executable:

chmod +x log_analyzer.sh

Replace "YOUR_GITHUB_REPOSITORY_URL" with your repository's actual clone URL.

Usage

Analyze the default authentication log:

sudo ./log_analyzer.sh

Analyze a specific log file:

./log_analyzer.sh -f sample_auth.log

Display the top five entries:

./log_analyzer.sh -f sample_auth.log -n 5

Set the alert threshold to five events:

./log_analyzer.sh -f sample_auth.log -t 5

Save the report:

./log_analyzer.sh -f sample_auth.log -o report.txt

Read logs from standard input:

cat sample_auth.log | ./log_analyzer.sh -f -

Display available options:

./log_analyzer.sh -h

Safe Testing

You can test the analyzer using a sample authentication log instead of a real system log.

Create a test file named "sample_auth.log":

Oct 29 10:10:01 server sshd[1001]: Failed password for root from 192.168.1.50 port 5001 ssh2
Oct 29 10:10:02 server sshd[1002]: Failed password for admin from 192.168.1.50 port 5002 ssh2
Oct 29 10:10:03 server sshd[1003]: Invalid user guest from 192.168.1.60 port 5003
Oct 29 10:10:04 server sshd[1004]: Accepted password for user from 192.168.1.10 port 5004 ssh2

Run the analyzer:

./log_analyzer.sh -f sample_auth.log -t 2

The repeated failed-password entries from "192.168.1.50" should trigger an alert.

Exit Codes

Code| Meaning
"0"| Analysis completed without threshold alerts
"1"| Usage, input, or output error
"2"| Analysis completed with threshold alerts

Technical Skills Demonstrated

- Bash scripting and Linux command-line tools
- Log parsing and text processing
- SSH authentication event analysis
- IP address extraction and validation
- Event counting and sorting
- Basic security alerting
- Report generation
- Input validation and temporary-file handling

Limitations

- Detection currently supports IPv4 addresses only.
- Thresholds are evaluated across the entire input log, not a configurable time window.
- Keyword-based service error detection may produce false positives.
- Log formats vary between Linux distributions.
- An alert indicates suspicious activity and does not prove that an attack occurred.
- The tool reports events; it does not block IP addresses or change firewall rules.

Future Improvements

- Add IPv6 support.
- Implement configurable time-window-based detection.
- Add automated regression tests.
- Support systemd journal logs.
- Export structured JSON reports.
- Improve service error classification.
- Integrate with monitoring and SIEM platforms.

Author

Cybersecurity and Linux security monitoring project.
