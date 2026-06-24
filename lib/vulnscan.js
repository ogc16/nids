const net = require('net');
const crypto = require('crypto');

const vulnerabilityDatabase = [
  { id: 'CVE-2021-44228', severity: 'Critical', cvssScore: 10.0, description: 'Apache Log4j2 JNDI features remote code execution', affectedSoftware: ['Apache Log4j 2.x'], affectedVersions: '2.0-beta9 - 2.14.1', remediation: 'Upgrade Log4j to 2.15.0+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'] },
  { id: 'CVE-2017-0144', severity: 'Critical', cvssScore: 9.3, description: 'SMBv1 remote code execution (EternalBlue)', affectedSoftware: ['Microsoft Windows'], affectedVersions: 'Windows Vista/7/8.1/10, Server 2008/2012/2016', remediation: 'Apply MS17-010 patch, disable SMBv1', references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-0144'] },
  { id: 'CVE-2019-0708', severity: 'Critical', cvssScore: 9.8, description: 'Remote Desktop Services remote code execution (BlueKeep)', affectedSoftware: ['Microsoft Windows RDP'], affectedVersions: 'Windows 7/Server 2008 R2/Server 2008/XP', remediation: 'Apply patch from KB4507456', references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-0708'] },
  { id: 'CVE-2014-0160', severity: 'High', cvssScore: 7.5, description: 'OpenSSL Heartbleed memory leak information disclosure', affectedSoftware: ['OpenSSL'], affectedVersions: '1.0.1 through 1.0.1f', remediation: 'Upgrade OpenSSL to 1.0.1g+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2014-0160'] },
  { id: 'CVE-2021-26855', severity: 'High', cvssScore: 9.1, description: 'Microsoft Exchange Server SSRF (ProxyLogon)', affectedSoftware: ['Microsoft Exchange Server'], affectedVersions: '2013/2016/2019', remediation: 'Apply March 2021 security updates', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-26855'] },
  { id: 'CVE-2021-34527', severity: 'Critical', cvssScore: 9.8, description: 'Windows Print Spooler remote code execution (PrintNightmare)', affectedSoftware: ['Microsoft Windows Print Spooler'], affectedVersions: 'Windows 7/8.1/10/11, Server 2008/2012/2016/2019/2022', remediation: 'Apply security update, disable Print Spooler if not needed', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-34527'] },
  { id: 'CVE-2020-1472', severity: 'Critical', cvssScore: 10.0, description: 'Netlogon privilege escalation (Zerologon)', affectedSoftware: ['Microsoft Windows Netlogon'], affectedVersions: 'Windows Server 2008/2012/2016/2019', remediation: 'Apply August 2020 security update, enforce secure RPC', references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-1472'] },
  { id: 'CVE-2020-0601', severity: 'Critical', cvssScore: 8.1, description: 'Windows CryptoAPI spoofing vulnerability', affectedSoftware: ['Microsoft Windows CryptoAPI'], affectedVersions: 'Windows 10/Server 2016/Server 2019', remediation: 'Apply January 2020 security update', references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-0601'] },
  { id: 'CVE-2021-40444', severity: 'Critical', cvssScore: 8.8, description: 'MSHTML remote code execution', affectedSoftware: ['Microsoft Windows MSHTML'], affectedVersions: 'Windows 7/8.1/10/11, Server 2008/2012/2016/2019/2022', remediation: 'Apply September 2021 security update', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-40444'] },
  { id: 'CVE-2022-22965', severity: 'Critical', cvssScore: 9.8, description: 'Spring Framework remote code execution (Spring4Shell)', affectedSoftware: ['Spring Framework'], affectedVersions: '5.3.0 - 5.3.17, 5.2.0 - 5.2.19', remediation: 'Upgrade Spring Framework to 5.3.18+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'] },
  { id: 'CVE-2020-0796', severity: 'Critical', cvssScore: 8.1, description: 'SMBv3 remote code execution (SMBGhost)', affectedSoftware: ['Microsoft Windows SMBv3'], affectedVersions: 'Windows 10 v1903/1909, Server 1903/1909', remediation: 'Apply March 2020 security update', references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-0796'] },
  { id: 'CVE-2021-26084', severity: 'High', cvssScore: 8.6, description: 'Confluence Server OGNL injection remote code execution', affectedSoftware: ['Atlassian Confluence Server'], affectedVersions: 'versions < 7.4.10, 7.11.6, 7.12.5, 7.13.0', remediation: 'Upgrade to patched version', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-26084'] },
  { id: 'CVE-2019-19781', severity: 'Critical', cvssScore: 9.8, description: 'Citrix ADC directory traversal', affectedSoftware: ['Citrix ADC', 'Citrix Gateway'], affectedVersions: '10.5/11.1/12.0/12.1/13.0', remediation: 'Apply Citrix-supplied mitigation steps', references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-19781'] },
  { id: 'CVE-2020-5902', severity: 'Critical', cvssScore: 9.8, description: 'F5 BIG-IP TMUI remote code execution', affectedSoftware: ['F5 BIG-IP'], affectedVersions: '11.6.x, 12.1.x, 13.1.x, 14.1.x, 15.0.x, 15.1.0', remediation: 'Upgrade to patched versions', references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-5902'] },
  { id: 'CVE-2021-22986', severity: 'High', cvssScore: 9.1, description: 'F5 BIG-IP iControl REST unauthenticated RCE', affectedSoftware: ['F5 BIG-IP'], affectedVersions: '11.6.x, 12.1.x, 13.1.x, 14.1.x, 15.1.x, 16.0.x', remediation: 'Upgrade BIG-IP to patched version', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-22986'] },
  { id: 'CVE-2020-14758', severity: 'High', cvssScore: 7.5, description: 'Oracle Database TNS listener poison', affectedSoftware: ['Oracle Database'], affectedVersions: '12.1/12.2/18c/19c', remediation: 'Apply Oracle Critical Patch Update', references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-14758'] },
  { id: 'CVE-2008-0166', severity: 'High', cvssScore: 7.5, description: 'Debian OpenSSL predictable random number generator', affectedSoftware: ['Debian OpenSSL'], affectedVersions: 'Debian-based systems with OpenSSL from 2006-2008', remediation: 'Regenerate all keys, upgrade openssl', references: ['https://nvd.nist.gov/vuln/detail/CVE-2008-0166'] },
  { id: 'CVE-2020-16898', severity: 'High', cvssScore: 7.8, description: 'Windows TCP/IP remote code execution (Bad Neighbor)', affectedSoftware: ['Microsoft Windows TCP/IP'], affectedVersions: 'Windows 10 v2004/20H2, Server 2004/20H2', remediation: 'Apply October 2020 security update', references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-16898'] },
  { id: 'CVE-2021-1675', severity: 'High', cvssScore: 7.5, description: 'Windows Print Spooler RCE', affectedSoftware: ['Microsoft Windows Print Spooler'], affectedVersions: 'Windows 7/8.1/10/11, Server 2008/2012/2016/2019/2022', remediation: 'Apply June 2021 security update', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-1675'] },
  { id: 'CVE-2022-30190', severity: 'High', cvssScore: 7.8, description: 'Microsoft Support Diagnostic Tool RCE (Follina)', affectedSoftware: ['Microsoft Windows MSDT'], affectedVersions: 'Windows 10/11, Server 2019/2022', remediation: 'Apply May 2022 security update', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-30190'] },
  { id: 'CVE-2021-31207', severity: 'Medium', cvssScore: 6.6, description: 'Microsoft Exchange Server SSRF', affectedSoftware: ['Microsoft Exchange Server'], affectedVersions: '2013/2016/2019', remediation: 'Apply May 2021 security updates', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-31207'] },
  { id: 'CVE-2021-31166', severity: 'High', cvssScore: 8.8, description: 'Windows HTTP protocol stack RCE', affectedSoftware: ['Microsoft Windows HTTP.sys'], affectedVersions: 'Windows 10 2004/20H2, Server 2004/20H2', remediation: 'Apply May 2021 security update', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-31166'] },
  { id: 'CVE-2017-5638', severity: 'High', cvssScore: 7.5, description: 'Apache Struts 2 RCE via Content-Type header', affectedSoftware: ['Apache Struts 2'], affectedVersions: '2.3.5 - 2.3.31, 2.5 - 2.5.10', remediation: 'Upgrade Apache Struts to 2.3.32+ or 2.5.10.1+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-5638'] },
  { id: 'CVE-2018-11776', severity: 'High', cvssScore: 8.1, description: 'Apache Struts 2 RCE via namespace', affectedSoftware: ['Apache Struts 2'], affectedVersions: '2.3 - 2.3.34, 2.5 - 2.5.16', remediation: 'Upgrade to Struts 2.3.35+ or 2.5.17+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2018-11776'] },
  { id: 'CVE-2019-11510', severity: 'Critical', cvssScore: 10.0, description: 'Pulse Secure SSL VPN arbitrary file read', affectedSoftware: ['Pulse Connect Secure'], affectedVersions: '8.2R12.1, 9.0R3.3, 9.1R1.6', remediation: 'Apply vendor-supplied patch', references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-11510'] },
  { id: 'CVE-2021-22893', severity: 'Critical', cvssScore: 9.9, description: 'Pulse Secure SSL VPN RCE', affectedSoftware: ['Pulse Connect Secure'], affectedVersions: '9.0R3, 9.1R1', remediation: 'Apply Pulse Secure SA44784 patch', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-22893'] },
  { id: 'CVE-2020-3452', severity: 'Medium', cvssScore: 5.3, description: 'Cisco ASA/FTD path traversal allowing file read', affectedSoftware: ['Cisco ASA', 'Cisco FTD'], affectedVersions: 'ASA 9.6/9.7/9.8/9.9/9.10/9.12/9.13/9.14, FTD 6.x', remediation: 'Upgrade to patched Cisco release', references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-3452'] },
  { id: 'CVE-2021-1609', severity: 'Medium', cvssScore: 6.5, description: 'Cisco ASA/FTD web services DoS', affectedSoftware: ['Cisco ASA', 'Cisco FTD'], affectedVersions: 'ASA 9.12/9.13/9.14, FTD 6.6/6.7', remediation: 'Upgrade to patched release', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-1609'] },
  { id: 'CVE-2022-0847', severity: 'High', cvssScore: 7.8, description: 'Linux kernel Dirty Pipe privilege escalation', affectedSoftware: ['Linux Kernel'], affectedVersions: '5.8 - 5.16.11, 5.15.25, 5.10.102', remediation: 'Upgrade kernel to 5.16.11+, 5.15.25+, 5.10.102+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-0847'] },
  { id: 'CVE-2022-0492', severity: 'Medium', cvssScore: 4.4, description: 'Linux kernel container escape via cgroup v1 release_agent', affectedSoftware: ['Linux Kernel'], affectedVersions: 'versions with cgroup v1 enabled', remediation: 'Apply kernel patch, use cgroup v2', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-0492'] },
  { id: 'CVE-2021-4034', severity: 'High', cvssScore: 7.8, description: 'Linux polkit pkexec privilege escalation (PwnKit)', affectedSoftware: ['Linux polkit'], affectedVersions: 'all versions prior to 0.120', remediation: 'Update polkit to 0.120+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-4034'] },
  { id: 'CVE-2014-6271', severity: 'Critical', cvssScore: 9.8, description: 'GNU Bash Shellshock environment variable code injection', affectedSoftware: ['GNU Bash'], affectedVersions: '1.0.3 - 4.3', remediation: 'Update bash to 4.3+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2014-6271'] },
  { id: 'CVE-2007-2447', severity: 'High', cvssScore: 7.5, description: 'Samba MS-RPC shell command injection', affectedSoftware: ['Samba'], affectedVersions: '3.0.0 - 3.0.25rc3', remediation: 'Upgrade Samba to 3.0.25+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2007-2447'] },
  { id: 'CVE-2017-7494', severity: 'High', cvssScore: 7.5, description: 'Samba remote code execution (SambaCry)', affectedSoftware: ['Samba'], affectedVersions: '3.5.0 - 4.6.4', remediation: 'Upgrade Samba to 4.6.4+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-7494'] },
  { id: 'CVE-2021-30563', severity: 'High', cvssScore: 7.8, description: 'Google Chrome V8 type confusion', affectedSoftware: ['Google Chrome'], affectedVersions: 'versions < 91.0.4472.164', remediation: 'Upgrade Chrome to 91.0.4472.164+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-30563'] },
  { id: 'CVE-2022-1096', severity: 'High', cvssScore: 8.8, description: 'Chrome V8 type confusion', affectedSoftware: ['Google Chrome'], affectedVersions: 'versions < 99.0.4844.84', remediation: 'Upgrade Chrome to 99.0.4844.84+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-1096'] },
  { id: 'CVE-2021-38003', severity: 'High', cvssScore: 8.8, description: 'Google Chrome V8 insufficient validation', affectedSoftware: ['Google Chrome'], affectedVersions: 'versions < 95.0.4638.69', remediation: 'Upgrade Chrome to 95.0.4638.69+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-38003'] },
  { id: 'CVE-2022-1388', severity: 'Critical', cvssScore: 9.8, description: 'F5 BIG-IP iControl REST unauthenticated RCE', affectedSoftware: ['F5 BIG-IP'], affectedVersions: '16.1.0 - 16.1.2, 15.1.0 - 15.1.5, 14.1.0 - 14.1.4, 13.1.0 - 13.1.4, 12.1.0 - 12.1.6', remediation: 'Upgrade BIG-IP to patched version', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-1388'] },
  { id: 'CVE-2022-29464', severity: 'Critical', cvssScore: 9.8, description: 'WSO2 arbitrary file upload RCE', affectedSoftware: ['WSO2 API Manager', 'WSO2 Identity Server'], affectedVersions: 'multiple WSO2 products 2.2.0 - 4.0.0', remediation: 'Apply vendor-supplied patch', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-29464'] },
  { id: 'CVE-2022-22963', severity: 'High', cvssScore: 7.5, description: 'Spring Cloud Function SpEL RCE', affectedSoftware: ['Spring Cloud Function'], affectedVersions: '3.0.0 - 3.2.5', remediation: 'Upgrade to 3.1.7+ or 3.2.6+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-22963'] },
  { id: 'CVE-2021-39237', severity: 'Medium', cvssScore: 4.6, description: 'Apache Tomcat information disclosure', affectedSoftware: ['Apache Tomcat'], affectedVersions: '9.0.0-M1 - 9.0.54, 10.0.0-M1 - 10.0.14', remediation: 'Upgrade Tomcat to 9.0.55+ or 10.0.15+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-39237'] },
  { id: 'CVE-2022-23181', severity: 'Medium', cvssScore: 5.5, description: 'Apache Tomcat local privilege escalation', affectedSoftware: ['Apache Tomcat'], affectedVersions: '10.1.0-M1, 9.0.0-M1 - 9.0.58, 8.5.0 - 8.5.72', remediation: 'Upgrade Tomcat to 10.1.1+, 9.0.59+, 8.5.73+', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-23181'] },
  { id: 'CVE-2020-25613', severity: 'Medium', cvssScore: 6.5, description: 'HTTPoxy vulnerability in HTTP client libraries', affectedSoftware: ['HTTP client libraries'], affectedVersions: 'various', remediation: 'Configure application to not send Proxy header', references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-25613'] },
];

const SCAN_STATES = { PENDING: 'pending', RUNNING: 'running', COMPLETED: 'completed', CANCELLED: 'cancelled', FAILED: 'failed' };

const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017];

const portServiceMap = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
  1521: 'Oracle DB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
  6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9090: 'WebAdmin', 27017: 'MongoDB'
};

const mitreMapping = {
  'CVE-2021-44228': ['T1203', 'T1190'],
  'CVE-2017-0144': ['T1210', 'T1190'],
  'CVE-2019-0708': ['T1210', 'T1190'],
  'CVE-2014-0160': ['T1213', 'T1040'],
  'CVE-2021-26855': ['T1190', 'T1133'],
  'CVE-2021-34527': ['T1068', 'T1203'],
  'CVE-2020-1472': ['T1068', 'T1552'],
  'CVE-2020-0601': ['T1557', 'T1588'],
  'CVE-2021-40444': ['T1203', 'T1190'],
  'CVE-2022-22965': ['T1190', 'T1203'],
  'CVE-2020-0796': ['T1210', 'T1190'],
  'CVE-2021-26084': ['T1190', 'T1203'],
  'CVE-2019-19781': ['T1190', 'T1133'],
  'CVE-2020-5902': ['T1190', 'T1203'],
  'CVE-2021-22986': ['T1190', 'T1106'],
  'CVE-2020-14758': ['T1200', 'T1557'],
  'CVE-2008-0166': ['T1600', 'T1552'],
  'CVE-2020-16898': ['T1203', 'T1499'],
  'CVE-2021-1675': ['T1068', 'T1203'],
  'CVE-2022-30190': ['T1203', 'T1190'],
  'CVE-2021-31207': ['T1190', 'T1133'],
  'CVE-2021-31166': ['T1203'],
  'CVE-2017-5638': ['T1190', 'T1203'],
  'CVE-2018-11776': ['T1190', 'T1203'],
  'CVE-2019-11510': ['T1190', 'T1021'],
  'CVE-2021-22893': ['T1190', 'T1203'],
  'CVE-2020-3452': ['T1190', 'T1041'],
  'CVE-2021-1609': ['T1498'],
  'CVE-2022-0847': ['T1068', 'T1055'],
  'CVE-2022-0492': ['T1068', 'T1611'],
  'CVE-2021-4034': ['T1068', 'T1548'],
  'CVE-2014-6271': ['T1203', 'T1190'],
  'CVE-2007-2447': ['T1203', 'T1210'],
  'CVE-2017-7494': ['T1203', 'T1210'],
  'CVE-2021-30563': ['T1203'],
  'CVE-2022-1096': ['T1203'],
  'CVE-2021-38003': ['T1203'],
  'CVE-2022-1388': ['T1190', 'T1106'],
  'CVE-2022-29464': ['T1190', 'T1505'],
  'CVE-2022-22963': ['T1190', 'T1203'],
  'CVE-2021-39237': ['T1592', 'T1082'],
  'CVE-2022-23181': ['T1068'],
  'CVE-2020-25613': ['T1090', 'T1557'],
};

const mitigationPreventionMap = {
  'Web Application': { measures: ['WAF rules', 'Input validation', 'Output encoding', 'CSRF tokens', 'Rate limiting'], technologies: ['mod_security', 'Cloudflare WAF', 'AWS WAF', 'Signal Sciences'] },
  'Database': { measures: ['Least privilege', 'Encryption at rest', 'Connection encryption', 'Audit logging'], technologies: ['Database Activity Monitoring', 'Vault for secrets'] },
  'Network Device': { measures: ['Access control lists', 'Segment networks', 'Disable unused services', 'Update firmware'], technologies: ['NAC', '802.1X', 'Zero Trust'] },
  'Operating System': { measures: ['Patch management', 'Endpoint protection', 'App whitelisting', 'Minimal attack surface'], technologies: ['EDR', 'Antivirus', 'CIS benchmarks'] },
  'Server': { measures: ['Harden configuration', 'Limit exposed ports', 'Regular patching', 'Intrusion detection'], technologies: ['HIDS', 'File integrity monitoring', 'Configuration management'] },
  'Firewall': { measures: ['Rule review', 'Minimal ruleset', 'Anomaly detection', 'Regular audits'], technologies: ['NGFW', 'IPS', 'Log analytics'] },
};

const scans = [];

function checkPort(target, port, timeout = 3000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(timeout);
    sock.on('connect', () => { sock.destroy(); resolve(true); });
    sock.on('error', () => { sock.destroy(); resolve(false); });
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
    sock.connect(port, target);
  });
}

function attemptBannerGrab(target, port, timeout = 4000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(timeout);
    let banner = '';
    sock.on('connect', () => {
      const service = portServiceMap[port] || 'Unknown';
      const probe = { 21: 'SYST\r\n', 22: '', 25: '', 80: 'GET / HTTP/1.0\r\n\r\n', 110: '', 143: '', 443: '', 445: '', 8080: 'GET / HTTP/1.0\r\n\r\n' };
      if (probe[port]) sock.write(probe[port]);
    });
    sock.on('data', (data) => { banner += data.toString('utf8', 0, Math.min(data.length, 512)); sock.destroy(); });
    sock.on('error', () => sock.destroy());
    sock.on('timeout', () => sock.destroy());
    sock.on('close', () => resolve(banner || null));
    sock.connect(port, target);
  });
}

async function scanPorts(target, ports) {
  const results = [];
  for (const port of ports) {
    const open = await checkPort(target, port);
    const service = portServiceMap[port] || 'Unknown';
    results.push({ port, service, open });
  }
  return results;
}

async function scanCommonPorts(target) {
  return scanPorts(target, commonPorts);
}

async function scanServiceVersion(target, port) {
  const open = await checkPort(target, port);
  if (!open) return { port, open: false, service: null, banner: null, version: null };
  const banner = await attemptBannerGrab(target, port);
  let version = null;
  if (banner) {
    const patterns = {
      ssh: /SSH-([\d.]+)/i, apache: /Apache\/([\d.]+)/i, nginx: /nginx\/([\d.]+)/i,
      openssl: /OpenSSL\/([\d.abcfghklmprsu]+)/i, mysql: /mysql.*?([\d.]+)/i,
      iis: /IIS\/([\d.]+)/i, exim: /Exim\s+([\d.]+)/i, sendmail: /Sendmail\s+([\d.]+)/i,
      pureftp: /Pure-FTPd\s+([\d.]+)/i, profTPD: /ProFTPD\s+([\d.]+)/i, vsftpd: /vsFTPd\s+([\d.]+)/i,
    };
    for (const [, re] of Object.entries(patterns)) {
      const m = banner.match(re);
      if (m) { version = m[1]; break; }
    }
  }
  return { port, open: true, service: portServiceMap[port] || 'Unknown', banner, version };
}

function assessAsset(asset) {
  const vulns = [];
  const assetName = (asset.name || asset.hostname || 'Unknown').toLowerCase();
  const assetType = asset.type || 'Server';
  const ports = asset.ports || [];
  const services = asset.services || {};
  const software = asset.software || [];

  const allPlatformCandidates = vulnerabilityDatabase.filter(v => {
    const swMatch = v.affectedSoftware.some(s => {
      const sl = s.toLowerCase();
      if (ports.some(p => {
        const svc = (portServiceMap[p] || '').toLowerCase();
        return sl.includes(svc) || svc.includes(sl);
      })) return true;
      if (software.some(sw => sw.toLowerCase().includes(sl) || sl.includes(sw.toLowerCase()))) return true;
      if (assetName.includes(sl) || sl.includes(assetName)) return true;
      return false;
    });
    return swMatch;
  });

  for (const vuln of allPlatformCandidates) {
    vulns.push({ ...vuln, matchedOn: 'asset_profile', status: 'unpatched', detectedAt: new Date().toISOString() });
  }

  if (ports.includes(445) && ports.includes(139) && !allPlatformCandidates.some(v => v.id === 'CVE-2017-0144')) {
    vulns.push({ ...vulnerabilityDatabase.find(v => v.id === 'CVE-2017-0144'), matchedOn: 'open_port_smb', status: 'potential', detectedAt: new Date().toISOString() });
  }
  if (ports.includes(3389) && !allPlatformCandidates.some(v => v.id === 'CVE-2019-0708')) {
    vulns.push({ ...vulnerabilityDatabase.find(v => v.id === 'CVE-2019-0708'), matchedOn: 'open_port_rdp', status: 'potential', detectedAt: new Date().toISOString() });
  }

  const critical = vulns.filter(v => v.severity === 'Critical').length;
  const high = vulns.filter(v => v.severity === 'High').length;
  const medium = vulns.filter(v => v.severity === 'Medium').length;
  const low = vulns.filter(v => v.severity === 'Low').length;

  const riskScore = Math.min(10, Math.round((critical * 3 + high * 2 + medium * 1) / Math.max(vulns.length, 1) * 2.5 * 10) / 10);

  return {
    assetId: asset.id || asset.hostname || 'unknown',
    assetName: asset.name || asset.hostname || 'Unknown',
    totalVulns: vulns.length,
    criticalCount: critical,
    highCount: high,
    mediumCount: medium,
    lowCount: low,
    vulnerabilities: vulns,
    riskScore: isNaN(riskScore) ? 0 : riskScore,
  };
}

function generateScanId() {
  return `SCAN-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

function startScan(targets) {
  if (!Array.isArray(targets)) targets = [targets];
  const scanId = generateScanId();
  const scan = {
    id: scanId, targets, status: SCAN_STATES.RUNNING, progress: 0, results: [],
    startedAt: new Date().toISOString(), completedAt: null, cancelled: false,
  };
  scans.push(scan);

  process.nextTick(async () => {
    const totalTasks = targets.reduce((sum, t) => {
      const ports = t.ports || commonPorts;
      return sum + ports.length + 1;
    }, 0);
    let completed = 0;

    for (const target of targets) {
      if (scan.cancelled) break;
      const ports = target.ports || commonPorts;
      const host = target.host || target;
      try {
        const portResults = [];
        for (const port of ports) {
          if (scan.cancelled) break;
          const open = await checkPort(host, port);
          portResults.push({ port, service: portServiceMap[port] || 'Unknown', open });
          completed++;
          scan.progress = Math.round((completed / totalTasks) * 100);
        }

        let versionData = {};
        const openPorts = portResults.filter(p => p.open);
        for (const pr of openPorts) {
          if (scan.cancelled) break;
          versionData[pr.port] = await scanServiceVersion(host, pr.port);
          completed++;
          scan.progress = Math.round((completed / totalTasks) * 100);
        }

        const assetProfile = {
          id: host, name: host, type: 'Server', hostname: host, ports: portResults.filter(p => p.open).map(p => p.port), services: versionData, software: [],
        };

        const assessment = assessAsset(assetProfile);
        scan.results.push({ target: host, ports: portResults, versions: versionData, assessment });
      } catch (err) {
        scan.results.push({ target: host, error: err.message });
      }
    }

    if (!scan.cancelled) {
      scan.status = SCAN_STATES.COMPLETED;
      scan.completedAt = new Date().toISOString();
      scan.progress = 100;
    }
  });

  return scanId;
}

function getScanStatus(scanId) {
  const scan = scans.find(s => s.id === scanId);
  if (!scan) return null;
  return { id: scan.id, status: scan.status, progress: scan.progress, startedAt: scan.startedAt, completedAt: scan.completedAt, targets: scan.targets };
}

function cancelScan(scanId) {
  const scan = scans.find(s => s.id === scanId);
  if (!scan) return false;
  if (scan.status === SCAN_STATES.RUNNING) {
    scan.cancelled = true;
    scan.status = SCAN_STATES.CANCELLED;
    scan.completedAt = new Date().toISOString();
    return true;
  }
  return false;
}

function getScanResults(scanId) {
  const scan = scans.find(s => s.id === scanId);
  if (!scan) return null;
  return { ...scan };
}

function getScanHistory() {
  return scans.map(s => ({
    id: s.id, targets: s.targets, status: s.status, progress: s.progress,
    startedAt: s.startedAt, completedAt: s.completedAt,
  }));
}

function suggestDetectionRules(vulnerability) {
  const cveId = vulnerability.id || vulnerability;
  const cve = typeof vulnerability === 'object' ? vulnerability : vulnerabilityDatabase.find(v => v.id === cveId);
  if (!cve) return [];

  const rules = [];
  const severity = cve.severity;
  const desc = cve.description.toLowerCase();

  const sigPriority = { Critical: 1, High: 2, Medium: 3, Low: 4 };

  if (desc.includes('remote code') || desc.includes('rce')) {
    rules.push({ type: 'signature', protocol: 'TCP', priority: sigPriority[severity] || 3, pattern: `RCE_EXPLOIT_${cve.id.replace(/[-\s]+/g, '_')}`, action: 'block', description: `Detect RCE attempts targeting ${cve.id}` });
    rules.push({ type: 'anomaly', metric: 'outbound_data_rate', threshold: 1000000, window: 60, priority: sigPriority[severity] || 3, description: `Anomalous outbound traffic following ${cve.id} exploit` });
  }
  if (desc.includes('sql') || desc.includes('injection')) {
    rules.push({ type: 'signature', protocol: 'HTTP', priority: 2, pattern: 'SQL_INJECTION_PATTERN', action: 'alert', description: `Detect SQL injection attempts related to ${cve.id}` });
  }
  if (desc.includes('xss') || desc.includes('cross-site')) {
    rules.push({ type: 'signature', protocol: 'HTTP', priority: 2, pattern: 'XSS_PATTERN', action: 'alert', description: `Detect XSS attempts related to ${cve.id}` });
  }
  if (desc.includes('privilege escalation') || desc.includes('eop')) {
    rules.push({ type: 'anomaly', metric: 'privilege_change_count', threshold: 5, window: 300, priority: sigPriority[severity] || 3, description: `Detect privilege escalation attempts targeting ${cve.id}` });
  }
  if (desc.includes('smb') || desc.includes('eternalblue')) {
    rules.push({ type: 'signature', protocol: 'SMB', priority: 1, pattern: 'ETERNALBLUE_EXPLOIT', action: 'block', description: `Detect SMB exploit targeting ${cve.id}` });
  }
  if (desc.includes('heartbleed') || desc.includes('tls') || desc.includes('openssl')) {
    rules.push({ type: 'signature', protocol: 'TLS', priority: 2, pattern: 'HEARTBEAT_MALFORMED', action: 'alert', description: `Detect malformed heartbeat for ${cve.id}` });
  }
  if (desc.includes('rdp') || desc.includes('bluekeep')) {
    rules.push({ type: 'signature', protocol: 'RDP', priority: 1, pattern: 'BLUEEKEEP_EXPLOIT', action: 'block', description: `Detect BlueKeep exploit targeting ${cve.id}` });
  }

  rules.push({
    type: 'correlation', priority: sigPriority[severity] || 3, minEvents: 2, timeWindow: 3600,
    conditions: [{ field: 'cve_id', value: cve.id }, { field: 'severity', value: severity.toLowerCase() }],
    description: `Correlate multiple events related to ${cve.id}`,
  });

  return rules;
}

function createIncidentFromVuln(vuln, asset) {
  const severity = vuln.severity;
  if (severity !== 'Critical' && severity !== 'High') return null;

  const incident = {
    id: `INC-${crypto.randomBytes(6).toString('hex').toUpperCase()}`,
    type: 'vulnerability',
    title: `${severity} vulnerability detected: ${vuln.id} on ${asset.assetName || asset.name || 'unknown'}`,
    description: vuln.description,
    severity,
    cvssScore: vuln.cvssScore,
    cveId: vuln.id,
    assetId: asset.assetId || asset.id,
    assetName: asset.assetName || asset.name,
    status: 'open',
    detectedAt: new Date().toISOString(),
    remediation: vuln.remediation,
    mitreTechniques: mitreMapping[vuln.id] || [],
    references: vuln.references || [],
    suggestedRules: suggestDetectionRules(vuln),
    priority: severity === 'Critical' ? 'immediate' : 'high',
    assignedTo: null,
    notes: [],
  };

  return incident;
}

function mapVulnToMitre(cveId) {
  const cve = vulnerabilityDatabase.find(v => v.id === cveId);
  const techniques = mitreMapping[cveId] || [];
  return {
    cveId,
    description: cve ? cve.description : 'Unknown vulnerability',
    severity: cve ? cve.severity : 'Unknown',
    mitreTechniques: techniques,
    techniqueDetails: techniques.map(t => ({ id: t, name: getMitreTechniqueName(t) })),
  };
}

function getMitreTechniqueName(techniqueId) {
  const names = {
    T1190: 'Exploit Public-Facing Application', T1203: 'Exploitation for Client Execution',
    T1210: 'Exploitation of Remote Services', T1213: 'Data from Information Repositories',
    T1133: 'External Remote Services', T1068: 'Exploitation for Privilege Escalation',
    T1552: 'Unsecured Credentials', T1557: 'Adversary-in-the-Middle',
    T1588: 'Obtain Capabilities', T1040: 'Network Sniffing',
    T1041: 'Exfiltration Over C2 Channel', T1498: 'Network Denial of Service',
    T1499: 'Endpoint Denial of Service', T1055: 'Process Injection',
    T1611: 'Escape to Host', T1548: 'Abuse Elevation Control Mechanism',
    T1106: 'Native API', T1505: 'Server Software Component',
    T1021: 'Remote Services', T1200: 'Hardware Additions',
    T1600: 'Weaken Encryption', T1592: 'Gather Victim Host Information',
    T1082: 'System Information Discovery', T1090: 'Proxy',
    T1553: 'Subvert Trust Controls', T1574: 'Hijack Execution Flow',
  };
  return names[techniqueId] || 'Unknown Technique';
}

function getVulnerabilityReport(filters = {}) {
  let filtered = [...vulnerabilityDatabase];

  if (filters.severity) {
    filtered = filtered.filter(v => v.severity.toLowerCase() === filters.severity.toLowerCase());
  }
  if (filters.minScore !== undefined) {
    filtered = filtered.filter(v => v.cvssScore >= filters.minScore);
  }
  if (filters.maxScore !== undefined) {
    filtered = filtered.filter(v => v.cvssScore <= filters.maxScore);
  }
  if (filters.search) {
    const s = filters.search.toLowerCase();
    filtered = filtered.filter(v => v.description.toLowerCase().includes(s) || v.id.toLowerCase().includes(s) || v.affectedSoftware.some(sw => sw.toLowerCase().includes(s)));
  }

  const bySeverity = { Critical: [], High: [], Medium: [], Low: [] };
  for (const v of filtered) {
    if (bySeverity[v.severity]) bySeverity[v.severity].push(v.id);
  }

  const avgScore = filtered.length ? filtered.reduce((s, v) => s + v.cvssScore, 0) / filtered.length : 0;

  return {
    totalVulnerabilities: filtered.length,
    generatedAt: new Date().toISOString(),
    filters,
    summary: {
      critical: bySeverity.Critical.length, high: bySeverity.High.length,
      medium: bySeverity.Medium.length, low: bySeverity.Low.length,
      averageCvssScore: Math.round(avgScore * 10) / 10,
    },
    breakdown: bySeverity,
    vulnerabilities: filtered,
  };
}

function getRemediationPlan() {
  const sorted = [...vulnerabilityDatabase].sort((a, b) => b.cvssScore - a.cvssScore);

  const plan = {
    generatedAt: new Date().toISOString(),
    totalVulnerabilities: sorted.length,
    criticalCount: sorted.filter(v => v.severity === 'Critical').length,
    highCount: sorted.filter(v => v.severity === 'High').length,
    mediumCount: sorted.filter(v => v.severity === 'Medium').length,
    lowCount: sorted.filter(v => v.severity === 'Low').length,
    prioritizedRemediations: sorted.map((v, i) => ({
      priority: i + 1,
      cveId: v.id,
      severity: v.severity,
      cvssScore: v.cvssScore,
      description: v.description,
      affectedSoftware: v.affectedSoftware,
      remediation: v.remediation,
      effort: v.severity === 'Critical' ? 'immediate' : v.severity === 'High' ? 'within_7_days' : v.severity === 'Medium' ? 'within_30_days' : 'within_90_days',
    })),
    recommendations: [
      { category: 'Patch Management', priority: 'critical', action: 'Apply all Critical severity patches immediately', affected: sorted.filter(v => v.severity === 'Critical').length },
      { category: 'Configuration Hardening', priority: 'high', action: 'Disable unused services (SMBv1, RDP if not needed)', affected: sorted.filter(v => v.description.toLowerCase().includes('smb') || v.description.toLowerCase().includes('rdp')).length },
      { category: 'Network Segmentation', priority: 'high', action: 'Segment critical assets from general network', affected: sorted.filter(v => v.cvssScore >= 9).length },
      { category: 'Access Control', priority: 'medium', action: 'Review and restrict administrative access', affected: sorted.filter(v => v.severity === 'High' || v.severity === 'Critical').length },
      { category: 'Monitoring Enhancement', priority: 'medium', action: 'Deploy additional detection rules for critical CVEs', affected: sorted.length },
    ],
  };

  return plan;
}

function getAssetRiskScore(assetId) {
  const scan = scans.find(s => s.results.some(r => r.assessment && r.assessment.assetId === assetId));
  if (!scan) return { assetId, riskScore: 0, riskLevel: 'unknown', message: 'No scan data found for asset' };

  const result = scan.results.find(r => r.assessment && r.assessment.assetId === assetId);
  if (!result || !result.assessment) return { assetId, riskScore: 0, riskLevel: 'unknown', message: 'No assessment data available' };

  const { riskScore, criticalCount, highCount, mediumCount, lowCount, totalVulns } = result.assessment;
  let riskLevel = 'low';
  if (riskScore >= 8) riskLevel = 'critical';
  else if (riskScore >= 6) riskLevel = 'high';
  else if (riskScore >= 4) riskLevel = 'medium';

  return {
    assetId,
    riskScore,
    riskLevel,
    totalVulnerabilities: totalVulns,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    assessedAt: new Date().toISOString(),
  };
}

module.exports = {
  vulnerabilityDatabase,
  scanPorts,
  scanCommonPorts,
  scanServiceVersion,
  assessAsset,
  startScan,
  getScanStatus,
  cancelScan,
  getScanResults,
  getScanHistory,
  suggestDetectionRules,
  createIncidentFromVuln,
  mapVulnToMitre,
  getVulnerabilityReport,
  getRemediationPlan,
  getAssetRiskScore,
};
