const mitreData = {
  tactics: [
    {
      id: 'TA0043',
      name: 'Reconnaissance',
      description: 'The adversary is gathering information to plan future operations.',
      techniques: [
        {
          id: 'T1595',
          name: 'Active Scanning',
          description: 'Adversaries execute active reconnaissance scans to gather information about the target environment.',
          detection: 'Monitor network traffic for scanning activity, port scans, and service enumeration probes.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1592',
          name: 'Gather Victim Host Information',
          description: 'Adversaries gather information about the victim\'s hosts to inform targeting.',
          detection: 'Monitor for suspicious queries to system information endpoints and configuration data.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1589',
          name: 'Gather Victim Identity Information',
          description: 'Adversaries gather identity information about the victim to inform targeting.',
          detection: 'Monitor for collection of user data, employee directories, or corporate databases.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1590',
          name: 'Gather Victim Network Information',
          description: 'Adversaries gather network information about the victim to inform targeting.',
          detection: 'Monitor DNS queries, whois lookups, and network mapping activities from non-admin sources.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1598',
          name: 'Phishing for Information',
          description: 'Adversaries send phishing messages to elicit sensitive information from targets.',
          detection: 'Monitor email gateway logs for suspicious sender domains, phishing indicators, and unusual attachment types.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1591',
          name: 'Gather Victim Org Information',
          description: 'Adversaries gather information about the victim\'s organization to inform targeting.',
          detection: 'Monitor for searches of corporate websites, job postings, and business partner listings.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        }
      ]
    },
    {
      id: 'TA0042',
      name: 'Resource Development',
      description: 'The adversary is establishing resources to support operations.',
      techniques: [
        {
          id: 'T1583',
          name: 'Acquire Infrastructure',
          description: 'Adversaries acquire infrastructure to support operations, including servers, domains, and certificates.',
          detection: 'Monitor for registration of new domains resembling legitimate services and acquisition of hosting services.',
          platforms: ['Cloud']
        },
        {
          id: 'T1588',
          name: 'Obtain Capabilities',
          description: 'Adversaries obtain capabilities such as malware, exploits, and tools to support operations.',
          detection: 'Monitor underground forums, code repositories, and tool sharing platforms for mentions of organization.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1587',
          name: 'Develop Capabilities',
          description: 'Adversaries develop malware, exploits, and other capabilities for their operations.',
          detection: 'Monitor for code compilation activity, packer/obfuscator usage, and test infrastructure.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1584',
          name: 'Compromise Infrastructure',
          description: 'Adversaries compromise third-party infrastructure to support operations.',
          detection: 'Monitor for anomalous administrative access to cloud services, hosting providers, and domain registrars.',
          platforms: ['Cloud']
        },
        {
          id: 'T1608',
          name: 'Stage Capabilities',
          description: 'Adversaries upload or otherwise stage capabilities for use during operations.',
          detection: 'Monitor file uploads to web servers, cloud storage, and code repositories for malicious content.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        }
      ]
    },
    {
      id: 'TA0001',
      name: 'Initial Access',
      description: 'The adversary is trying to get into your network.',
      techniques: [
        {
          id: 'T1566',
          name: 'Phishing',
          description: 'Adversaries send phishing messages to gain access to victim systems.',
          detection: 'Monitor email gateway logs for suspicious attachments, links, and sender impersonation attempts.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1190',
          name: 'Exploit Public-Facing Application',
          description: 'Adversaries exploit vulnerabilities in internet-facing applications to gain access.',
          detection: 'Monitor web server logs for exploit attempts, unusual parameters, and known vulnerability signatures.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1133',
          name: 'External Remote Services',
          description: 'Adversaries leverage external remote services like VPNs and RDP to gain initial access.',
          detection: 'Monitor authentication logs for unusual remote access patterns and geographic anomalies.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1078',
          name: 'Valid Accounts',
          description: 'Adversaries use legitimate credentials to gain initial access.',
          detection: 'Monitor for unusual authentication patterns, off-hours logins, and access from unfamiliar locations.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1189',
          name: 'Drive-by Compromise',
          description: 'Adversaries compromise systems through user visits to compromised websites.',
          detection: 'Monitor web proxy logs for connections to known malicious domains and exploit kit signatures.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1567',
          name: 'Spearphishing via Service',
          description: 'Adversaries use social media and other services to deliver spearphishing messages.',
          detection: 'Monitor for messages from known social media platforms requesting sensitive information.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1091',
          name: 'Replication Through Removable Media',
          description: 'Adversaries use removable media to gain access to air-gapped systems.',
          detection: 'Monitor for autorun.inf files, unusual USB device connections, and file writes to removable media.',
          platforms: ['Windows', 'Linux', 'macOS']
        }
      ]
    },
    {
      id: 'TA0002',
      name: 'Execution',
      description: 'The adversary is trying to run malicious code.',
      techniques: [
        {
          id: 'T1059',
          name: 'Command and Scripting Interpreter',
          description: 'Adversaries abuse command and script interpreters to execute commands.',
          detection: 'Monitor process creation events for PowerShell, cmd, bash, python, and other interpreter executions.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1204',
          name: 'User Execution',
          description: 'Adversaries rely on user action to execute malicious code.',
          detection: 'Monitor for suspicious file executions from email attachments, downloads, and removable media.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1047',
          name: 'Windows Management Instrumentation',
          description: 'Adversaries use WMI for execution of commands and scripts.',
          detection: 'Monitor WMI activity, wmic.exe and PowerShell commands using WMI objects.',
          platforms: ['Windows']
        },
        {
          id: 'T1053',
          name: 'Scheduled Task/Job',
          description: 'Adversaries use scheduled tasks to execute malicious code at specific times.',
          detection: 'Monitor creation of scheduled tasks, cron jobs, and at jobs via event logs.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1106',
          name: 'Native API',
          description: 'Adversaries directly invoke native API calls to execute malicious code.',
          detection: 'Monitor for direct syscall usage, API hooking bypasses, and anomalous API call patterns.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1559',
          name: 'Inter-Process Communication',
          description: 'Adversaries abuse IPC mechanisms to execute code in other processes.',
          detection: 'Monitor for DDE, COM, and OLE automation suspicious activity.',
          platforms: ['Windows', 'macOS']
        }
      ]
    },
    {
      id: 'TA0003',
      name: 'Persistence',
      description: 'The adversary is trying to maintain their foothold.',
      techniques: [
        {
          id: 'T1547',
          name: 'Boot or Logon Autostart Execution',
          description: 'Adversaries configure system settings to automatically execute code on boot or user login.',
          detection: 'Monitor registry Run keys, startup folders, launchd plists, and systemd service files.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1098',
          name: 'Account Manipulation',
          description: 'Adversaries manipulate accounts to maintain access.',
          detection: 'Monitor for account creation, credential changes, and permission modifications outside normal patterns.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1053',
          name: 'Scheduled Task/Job',
          description: 'Adversaries use scheduled tasks and cron jobs for persistence.',
          detection: 'Monitor creation and modification of scheduled tasks, cron entries, and launch agents.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1505',
          name: 'Server Software Component',
          description: 'Adversaries inject malicious code into server software for persistence.',
          detection: 'Monitor web shells, IIS modules, WordPress plugin modifications, and SQL stored procedures.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1136',
          name: 'Create Account',
          description: 'Adversaries create accounts to maintain access to victim systems.',
          detection: 'Monitor for new user account creation, especially service accounts and privileged accounts.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1543',
          name: 'Create or Modify System Process',
          description: 'Adversaries create or modify system services and daemons for persistence.',
          detection: 'Monitor service installation, Windows service creation, and launch daemon modifications.',
          platforms: ['Windows', 'Linux', 'macOS']
        }
      ]
    },
    {
      id: 'TA0004',
      name: 'Privilege Escalation',
      description: 'The adversary is trying to gain higher-level permissions.',
      techniques: [
        {
          id: 'T1068',
          name: 'Exploitation for Privilege Escalation',
          description: 'Adversaries exploit vulnerabilities to gain elevated privileges.',
          detection: 'Monitor for exploit toolkits, unusual system calls, and privilege escalation attempts.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1055',
          name: 'Process Injection',
          description: 'Adversaries inject code into other processes to elevate privileges.',
          detection: 'Monitor for process injection API calls, CreateRemoteThread, and memory modification patterns.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1548',
          name: 'Abuse Elevation Control Mechanism',
          description: 'Adversaries abuse mechanisms like sudo, UAC, and setuid to escalate privileges.',
          detection: 'Monitor UAC bypass techniques, sudo usage patterns, and setuid file modifications.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1574',
          name: 'Hijack Execution Flow',
          description: 'Adversaries hijack execution flow to load malicious code during process startup.',
          detection: 'Monitor DLL search order hijacking, path interception, and image hijacking attempts.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1037',
          name: 'Boot or Logon Initialization Scripts',
          description: 'Adversaries use initialization scripts to escalate privileges at boot.',
          detection: 'Monitor logon scripts, rc files, profile scripts, and policy-based initialization mechanisms.',
          platforms: ['Windows', 'Linux', 'macOS']
        }
      ]
    },
    {
      id: 'TA0005',
      name: 'Defense Evasion',
      description: 'The adversary is trying to avoid being detected.',
      techniques: [
        {
          id: 'T1562',
          name: 'Impair Defenses',
          description: 'Adversaries disable or tamper with security tools and logging.',
          detection: 'Monitor for disabling of security services, firewall rule changes, and audit log clearing.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1055',
          name: 'Process Injection',
          description: 'Adversaries inject code into trusted processes to evade defenses.',
          detection: 'Monitor for process injection API calls and anomalous access to process memory.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1070',
          name: 'Indicator Removal',
          description: 'Adversaries remove indicators of compromise to evade detection.',
          detection: 'Monitor for event log clearing, file deletion, timestomping, and artifact removal.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1027',
          name: 'Obfuscated Files or Information',
          description: 'Adversaries obfuscate files and data to evade detection.',
          detection: 'Monitor for encoding tools, packers, compression utilities, and base64 encoded commands.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1140',
          name: 'Deobfuscate/Decode Files or Information',
          description: 'Adversaries decode or decrypt obfuscated files for execution.',
          detection: 'Monitor execution of decoding tools, certificate utilities, and embedded script extraction.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1036',
          name: 'Masquerading',
          description: 'Adversaries rename or manipulate files to appear legitimate.',
          detection: 'Monitor for trusted system tools executing from unusual paths and renamed binaries.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1112',
          name: 'Modify Registry',
          description: 'Adversaries modify the Windows registry to evade defenses.',
          detection: 'Monitor registry modifications affecting security settings, autoruns, and system configuration.',
          platforms: ['Windows']
        },
        {
          id: 'T1497',
          name: 'Virtualization/Sandbox Evasion',
          description: 'Adversaries detect and avoid virtualization and analysis environments.',
          detection: 'Monitor for checks of VM artifacts, debugger detection, and sleep calls to bypass sandbox timeouts.',
          platforms: ['Windows', 'Linux', 'macOS']
        }
      ]
    },
    {
      id: 'TA0006',
      name: 'Credential Access',
      description: 'The adversary is trying to steal account names and passwords.',
      techniques: [
        {
          id: 'T1003',
          name: 'OS Credential Dumping',
          description: 'Adversaries dump credentials from operating systems and applications.',
          detection: 'Monitor LSASS memory access, SAM registry access, and credential dumping tool execution.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1555',
          name: 'Credentials from Password Stores',
          description: 'Adversaries extract credentials from password managers and keychains.',
          detection: 'Monitor access to password manager databases, keychain files, and credential vaults.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1056',
          name: 'Input Capture',
          description: 'Adversaries capture user input to obtain credentials.',
          detection: 'Monitor for keyloggers, API hooking of input functions, and on-screen keyboard interception.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1110',
          name: 'Brute Force',
          description: 'Adversaries use brute force techniques to guess credentials.',
          detection: 'Monitor for multiple failed authentication attempts, password spraying patterns, and credential stuffing.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1552',
          name: 'Unsecured Credentials',
          description: 'Adversaries search for credentials in files, configuration stores, and other locations.',
          detection: 'Monitor for searches of files containing passwords, configuration files with credentials, and browser credential stores.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1558',
          name: 'Steal or Forge Kerberos Tickets',
          description: 'Adversaries steal or forge Kerberos tickets to authenticate.',
          detection: 'Monitor for Kerberos ticket requests from unusual sources, golden ticket indicators, and ticket manipulation.',
          platforms: ['Windows']
        }
      ]
    },
    {
      id: 'TA0007',
      name: 'Discovery',
      description: 'The adversary is trying to figure out your environment.',
      techniques: [
        {
          id: 'T1087',
          name: 'Account Discovery',
          description: 'Adversaries enumerate accounts and account metadata.',
          detection: 'Monitor for net user/group queries, LDAP enumeration, and cloud account listing API calls.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1518',
          name: 'Software Discovery',
          description: 'Adversaries enumerate software installed on systems.',
          detection: 'Monitor for queries to software inventory, installed programs list, and package manager queries.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1069',
          name: 'Permission Groups Discovery',
          description: 'Adversaries enumerate group memberships and permissions.',
          detection: 'Monitor for group membership enumeration, permission listing, and role discovery commands.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1082',
          name: 'System Information Discovery',
          description: 'Adversaries gather system information about the compromised host.',
          detection: 'Monitor for hostname, OS version, systeminfo, and hardware enumeration commands.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1046',
          name: 'Network Service Discovery',
          description: 'Adversaries scan for services running on remote hosts.',
          detection: 'Monitor for port scans, service enumeration, and network connection probing.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1135',
          name: 'Network Share Discovery',
          description: 'Adversaries enumerate network shares accessible on systems.',
          detection: 'Monitor for net share commands, SMB enumeration, and network share mounting attempts.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1018',
          name: 'Remote System Discovery',
          description: 'Adversaries enumerate remote systems in the network.',
          detection: 'Monitor for ping sweeps, net view commands, ARP scans, and DNS enumeration.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1057',
          name: 'Process Discovery',
          description: 'Adversaries enumerate running processes on systems.',
          detection: 'Monitor for tasklist, ps commands, and process enumeration API calls.',
          platforms: ['Windows', 'Linux', 'macOS']
        }
      ]
    },
    {
      id: 'TA0008',
      name: 'Lateral Movement',
      description: 'The adversary is trying to move through your environment.',
      techniques: [
        {
          id: 'T1021',
          name: 'Remote Services',
          description: 'Adversaries use remote services like RDP, SSH, and WinRM to move laterally.',
          detection: 'Monitor for remote login events, RDP sessions, SSH connections, and WinRM usage.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1570',
          name: 'Lateral Tool Transfer',
          description: 'Adversaries transfer tools between systems during lateral movement.',
          detection: 'Monitor for file transfer activities over SMB, SCP, and administrative shares.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1550',
          name: 'Use Alternate Authentication Material',
          description: 'Adversaries use alternate authentication materials like pass-the-hash.',
          detection: 'Monitor for NTLM hash usage, pass-the-ticket activity, and authentication material reuse.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1072',
          name: 'Software Deployment Tools',
          description: 'Adversaries abuse software deployment tools for lateral movement.',
          detection: 'Monitor for SCCM, GPO, and other software deployment tool usage for unauthorized software pushes.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1091',
          name: 'Replication Through Removable Media',
          description: 'Adversaries use removable media to move between air-gapped systems.',
          detection: 'Monitor for autorun triggers, unusual file writes to removable media, and shortcut file manipulation.',
          platforms: ['Windows', 'Linux', 'macOS']
        }
      ]
    },
    {
      id: 'TA0009',
      name: 'Collection',
      description: 'The adversary is trying to gather data of interest.',
      techniques: [
        {
          id: 'T1005',
          name: 'Data from Local System',
          description: 'Adversaries collect data from local system sources.',
          detection: 'Monitor for bulk file access, collection of sensitive documents, and data aggregation activities.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1039',
          name: 'Data from Network Shared Drive',
          description: 'Adversaries collect data from network shares.',
          detection: 'Monitor for high-volume SMB reads, bulk file copies from network shares, and enumeration of shared folders.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1115',
          name: 'Clipboard Data',
          description: 'Adversaries collect data from the clipboard.',
          detection: 'Monitor for clipboard access API calls, clipboard viewer processes, and clipboard monitoring tools.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1025',
          name: 'Data from Removable Media',
          description: 'Adversaries collect data from removable media.',
          detection: 'Monitor for file copy operations from connected removable media and data exfiltration via USB.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1114',
          name: 'Email Collection',
          description: 'Adversaries collect email data from mail servers and clients.',
          detection: 'Monitor for mailbox access API calls, email forwarding rules, and bulk email download activities.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1056',
          name: 'Input Capture',
          description: 'Adversaries capture user input to collect data.',
          detection: 'Monitor for keylogging, form grabbing, and web input capture mechanisms.',
          platforms: ['Windows', 'Linux', 'macOS']
        }
      ]
    },
    {
      id: 'TA0011',
      name: 'Command and Control',
      description: 'The adversary is trying to communicate with compromised systems.',
      techniques: [
        {
          id: 'T1071',
          name: 'Application Layer Protocol',
          description: 'Adversaries use application layer protocols for C2 communication.',
          detection: 'Monitor for anomalous HTTP/HTTPS traffic patterns, DNS query patterns, and non-standard protocol usage.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1573',
          name: 'Encrypted Channel',
          description: 'Adversaries use encryption to obfuscate C2 traffic.',
          detection: 'Monitor for anomalous TLS handshakes, custom encryption, and non-standard SSL/TLS usage.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1095',
          name: 'Non-Application Layer Protocol',
          description: 'Adversaries use non-application layer protocols for C2.',
          detection: 'Monitor for raw TCP/UDP communication, ICMP tunneling, and protocol abuse.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1572',
          name: 'Protocol Tunneling',
          description: 'Adversaries tunnel C2 traffic through existing protocols.',
          detection: 'Monitor for DNS tunneling, SSH tunneling, and HTTP/HTTPS encapsulation of other protocols.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1102',
          name: 'Web Service',
          description: 'Adversaries use legitimate web services for C2 communication.',
          detection: 'Monitor for connections to cloud storage, social media, and collaboration tools from unusual processes.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1090',
          name: 'Proxy',
          description: 'Adversaries use proxies to obfuscate C2 traffic origin.',
          detection: 'Monitor for connections to known proxy services, Tor nodes, and anonymization networks.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        }
      ]
    },
    {
      id: 'TA0010',
      name: 'Exfiltration',
      description: 'The adversary is trying to steal data.',
      techniques: [
        {
          id: 'T1048',
          name: 'Exfiltration Over Alternative Protocol',
          description: 'Adversaries exfiltrate data over alternative protocols like FTP, SMTP, or DNS.',
          detection: 'Monitor for unusual outbound traffic on non-standard ports and protocols.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1567',
          name: 'Exfiltration Over Web Service',
          description: 'Adversaries exfiltrate data using web services like cloud storage and paste sites.',
          detection: 'Monitor for large data uploads to cloud storage, file sharing services, and paste sites.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1020',
          name: 'Automated Exfiltration',
          description: 'Adversaries use automated methods to continuously exfiltrate data.',
          detection: 'Monitor for scheduled tasks, cron jobs, and scripts performing regular data transfers.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1052',
          name: 'Exfiltration Over Physical Medium',
          description: 'Adversaries exfiltrate data via physical media.',
          detection: 'Monitor for unauthorized USB device connections, large file transfers to removable media, and physical access anomalies.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1030',
          name: 'Data Transfer Size Limits',
          description: 'Adversaries break data into smaller parts to evade detection.',
          detection: 'Monitor for fragmented file transfers, chunked data uploads, and multiple small outbound connections.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        }
      ]
    },
    {
      id: 'TA0040',
      name: 'Impact',
      description: 'The adversary is trying to manipulate, interrupt, or destroy your systems and data.',
      techniques: [
        {
          id: 'T1486',
          name: 'Data Encrypted for Impact',
          description: 'Adversaries encrypt data to disrupt availability and demand ransom.',
          detection: 'Monitor for mass file encryption, file extension changes, and ransomware notes being written to disk.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1485',
          name: 'Data Destruction',
          description: 'Adversaries destroy data on systems to disrupt operations.',
          detection: 'Monitor for mass file deletion, disk wiping utilities, and overwriting operations.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1496',
          name: 'Resource Hijacking',
          description: 'Adversaries use compromised resources for cryptomining or other unauthorized purposes.',
          detection: 'Monitor for anomalous CPU usage, cryptocurrency mining processes, and unauthorized resource consumption.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1499',
          name: 'Endpoint Denial of Service',
          description: 'Adversaries perform DoS attacks against endpoints.',
          detection: 'Monitor for traffic floods, resource exhaustion, and service degradation indicators.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        },
        {
          id: 'T1490',
          name: 'Inhibit System Recovery',
          description: 'Adversaries delete or remove backups to inhibit recovery.',
          detection: 'Monitor for backup deletion, volume shadow copy removal, and disaster recovery system tampering.',
          platforms: ['Windows', 'Linux', 'macOS']
        },
        {
          id: 'T1565',
          name: 'Data Manipulation',
          description: 'Adversaries manipulate data on systems for malicious effect.',
          detection: 'Monitor for unauthorized database modifications, data pipeline tampering, and file integrity violations.',
          platforms: ['Windows', 'Linux', 'macOS', 'Cloud']
        }
      ]
    }
  ]
};

const attackTypeMapping = {
  'C2 Communication': ['T1071', 'T1573', 'T1095', 'T1572', 'T1102', 'T1090'],
  'SQL Injection': ['T1190', 'T1505'],
  'Malware': ['T1204', 'T1059', 'T1547', 'T1055', 'T1027', 'T1070', 'T1486'],
  'Phishing': ['T1566', 'T1598', 'T1567'],
  'Ransomware': ['T1486', 'T1490', 'T1485', 'T1070', 'T1562'],
  'DDoS': ['T1498', 'T1499', 'T1496'],
  'Brute Force': ['T1110', 'T1078'],
  'Insider Threat': ['T1078', 'T1005', 'T1039', 'T1098', 'T1136'],
  'Web Exploitation': ['T1190', 'T1505', 'T1102', 'T1071'],
  'Supply Chain': ['T1195', 'T1588', 'T1584'],
  'Credential Theft': ['T1003', 'T1555', 'T1552', 'T1558', 'T1056'],
  'Lateral Movement': ['T1021', 'T1570', 'T1550', 'T1072'],
  'Data Exfiltration': ['T1048', 'T1567', 'T1020', 'T1052', 'T1030'],
  'Reconnaissance': ['T1595', 'T1592', 'T1589', 'T1590', 'T1591', 'T1598'],
  'Cryptomining': ['T1496'],
  'Living off the Land': ['T1059', 'T1047', 'T1053', 'T1106', 'T1087', 'T1069', 'T1082'],
  'Zero Day Exploit': ['T1190', 'T1068', 'T1204'],
  'Man in the Middle': ['T1557', 'T1040'],
  'Password Spraying': ['T1110'],
  'Domain Escalation': ['T1558', 'T1484', 'T1078']
};

const detectionLibrary = {
  'T1071': ['Network traffic analysis for anomalous HTTP/S headers and user agents', 'DNS query monitoring for domain generation algorithm patterns', 'TLS fingerprint analysis for JA3/JA3S anomalies'],
  'T1566': ['Email gateway sandbox analysis for attachment behavior', 'Sender reputation and SPF/DKIM/DMARC verification', 'URL analysis and click-time protection'],
  'T1190': ['WAF rule monitoring and false positive analysis', 'Vulnerability scanner correlation with exploit attempts', 'Web server log analysis for parameter tampering'],
  'T1059': ['Process lineage tracking for interpreter execution', 'Command-line argument logging and analysis', 'Script block logging for PowerShell'],
  'T1003': ['LSASS process access monitoring', 'Event ID 4663 for SAM registry access', 'Credential dumping tool signature detection'],
  'T1021': ['Remote login event correlation across systems', 'RDP/SSH session duration and time analysis', 'Network connection monitoring for lateral movement patterns'],
  'T1486': ['File extension change monitoring', 'Mass file read/write operation detection', 'Ransomware process behavior analysis'],
  'T1048': ['Data volume threshold monitoring per destination', 'Protocol anomaly detection for exfiltration channels', 'DNS TXT record size monitoring'],
  'T1070': ['Event log clearing alerting', 'File deletion monitoring in sensitive directories', 'Timestomping detection via file metadata analysis'],
  'T1562': ['Security service status monitoring', 'Firewall rule change auditing', 'SIEM agent heartbeat monitoring'],
  'T1027': ['Base64/hex encoded command detection', 'Packer/obfuscator tool execution monitoring', 'Suspicious PowerShell encoding patterns'],
  'T1110': ['Failed login threshold alerting', 'Account lockout monitoring', 'Geographic anomaly detection for logins'],
  'T1547': ['Registry Run key monitoring', 'Startup folder change detection', 'Launchd plist file modification monitoring'],
  'T1055': ['Cross-process access monitoring', 'Remote thread creation detection', 'Memory region permission changes'],
  'T1068': ['Exploit kit signature detection', 'Vulnerability scan correlation with exploitation events', 'System call anomaly detection'],
  'T1490': ['Backup deletion monitoring', 'Volume Shadow Copy service status', 'Recovery partition modification detection'],
  'T1090': ['Proxy detection via traffic analysis', 'Tor exit node IP correlation', 'VPN protocol fingerprinting'],
  'T1046': ['Port scan detection via connection monitoring', 'Service banner grabbing detection', 'Network reconnaissance pattern analysis'],
  'T1082': ['System information command execution monitoring', 'Hostname/OS enumeration detection', 'Hardware inventory query monitoring'],
  'T1018': ['Ping sweep detection via ICMP analysis', 'ARP scan detection', 'Net view command monitoring'],
  'T1570': ['File transfer event monitoring over SMB/SCP', 'Administrative share access logging', 'Large file transfer anomaly detection'],
  'T1078': ['Authentication pattern anomaly detection', 'Off-hours access monitoring', 'Unusual geographic login correlation'],
  'T1555': ['Password manager database access monitoring', 'Keychain/file access auditing', 'Credential vault API call monitoring'],
  'T1098': ['Account creation/modification auditing', 'Privilege escalation monitoring', 'Service principal name modification detection'],
  'T1053': ['Scheduled task creation monitoring', 'Cron job modification detection', 'At job command logging']
};

function flattenTechniques() {
  const result = [];
  for (const tactic of mitreData.tactics) {
    for (const technique of tactic.techniques) {
      result.push({ ...technique, tacticId: tactic.id, tacticName: tactic.name });
    }
  }
  return result;
}

const flatTechniques = flattenTechniques();

function getTactics() {
  return mitreData.tactics;
}

function getTechniques() {
  return flatTechniques;
}

function getTechniquesByTactic(tacticId) {
  const tactic = mitreData.tactics.find(t => t.id === tacticId);
  return tactic ? tactic.techniques : [];
}

function getTacticById(id) {
  return mitreData.tactics.find(t => t.id === id) || null;
}

function getTechniqueById(id) {
  return flatTechniques.find(t => t.id === id) || null;
}

function search(query) {
  if (!query || typeof query !== 'string') return { tactics: [], techniques: [] };
  const q = query.toLowerCase();
  const tactics = mitreData.tactics.filter(t =>
    t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q) || t.id.toLowerCase().includes(q)
  );
  const techniques = flatTechniques.filter(t =>
    t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q) || t.id.toLowerCase().includes(q)
  );
  return { tactics, techniques };
}

function getTechniquesByPlatform(platform) {
  return flatTechniques.filter(t => t.platforms && t.platforms.some(p => p.toLowerCase() === platform.toLowerCase()));
}

function getMitreData() {
  return mitreData;
}

function mapAttackTypeToTechniques(attackType) {
  const key = Object.keys(attackTypeMapping).find(
    k => k.toLowerCase() === attackType.toLowerCase()
  );
  if (!key) return [];
  return attackTypeMapping[key]
    .map(id => getTechniqueById(id))
    .filter(Boolean);
}

function getRecommendedDetections(techniqueIds) {
  if (!Array.isArray(techniqueIds)) return {};
  const result = {};
  for (const id of techniqueIds) {
    const technique = getTechniqueById(id);
    if (technique) {
      result[id] = {
        technique: `${technique.id} - ${technique.name}`,
        detection: technique.detection,
        recommendations: detectionLibrary[id] || ['Standard network and endpoint monitoring', 'Baseline traffic profiling', 'Correlation with threat intelligence feeds']
      };
    }
  }
  return result;
}

module.exports = {
  getTactics,
  getTechniques,
  getTechniquesByTactic,
  getTacticById,
  getTechniqueById,
  search,
  getTechniquesByPlatform,
  getMitreData,
  mapAttackTypeToTechniques,
  getRecommendedDetections
};
