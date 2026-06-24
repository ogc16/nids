const { execSync } = require('child_process');
const os = require('os');

function runPowerShell(script) {
  try {
    const cmd = `[Console]::OutputEncoding = [Text.Encoding]::UTF8; ${script}`;
    const raw = execSync(`powershell -NoProfile -NonInteractive -Command "&{${cmd}}"`, { encoding: 'utf8', timeout: 15000, maxBuffer: 10 * 1024 * 1024 });
    const trimmed = raw.trim();
    if (!trimmed) return [];
    try { return JSON.parse(trimmed); } catch { return trimmed; }
  } catch (err) {
    try { return JSON.parse(err.stdout?.trim() || '[]'); } catch { return []; }
  }
}

function getConnections() {
  const script = `
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Bound' } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{N='ProcessName';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName}catch{'unknown'}}}, @{N='CreationTime';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).StartTime.ToString('o')}catch{''}}};
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, @{N='RemoteAddress';E={''}}, @{N='RemotePort';E={0}}, @{N='State';E={'Listening'}}, OwningProcess, @{N='ProcessName';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName}catch{'unknown'}}}, @{N='CreationTime';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).StartTime.ToString('o')}catch{''}}};
    $conns + $udp | ConvertTo-Json -Compress
  `;
  return runPowerShell(script);
}

function getOpenPorts() {
  const script = `
    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Listen' } | Select-Object @{N='Protocol';E={'TCP'}}, LocalAddress, LocalPort, State, OwningProcess, @{N='ProcessName';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName}catch{'unknown'}}}, @{N='ProcessPath';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).Path}catch{''}}}, @{N='User';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop -IncludeUserName).UserName}catch{''}}};
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object @{N='Protocol';E={'UDP'}}, LocalAddress, LocalPort, @{N='State';E={'Listening'}}, OwningProcess, @{N='ProcessName';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName}catch{'unknown'}}}, @{N='ProcessPath';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).Path}catch{''}}}, @{N='User';E={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop -IncludeUserName).UserName}catch{''}}};
    $tcp + $udp | Sort-Object LocalPort | ConvertTo-Json -Compress
  `;
  return runPowerShell(script);
}

function getProcessDetail(pid) {
  const script = `
    $p = Get-Process -Id ${parseInt(pid)} -ErrorAction SilentlyContinue;
    if ($p) {
      [PSCustomObject]@{
        Id = $p.Id;
        ProcessName = $p.ProcessName;
        CPU = $p.CPU;
        WorkingSet = $p.WorkingSet64;
        VirtualSize = $p.VirtualMemorySize64;
        StartTime = $p.StartTime.ToString('o');
        Responding = $p.Responding;
        Threads = $p.Threads.Count;
        Handles = $p.HandleCount;
        Path = $p.Path;
        CommandLine = try{(Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)").CommandLine}catch{''};
        User = try{$p.GetOwner().User}catch{''}
      } | ConvertTo-Json -Compress
    } else { 'null' }
  `;
  return runPowerShell(script);
}

function getNetworkInterfaces() {
  const script = `
    Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, Status, LinkSpeed, @{N='IPv4';E={(Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ', '}}, @{N='MAC';E={$_.MacAddress}} | ConvertTo-Json -Compress
  `;
  return runPowerShell(script);
}

function getTrafficStats() {
  const interfaces = os.networkInterfaces();
  const stats = [];
  for (const [name, addrs] of Object.entries(interfaces)) {
    if (!addrs) continue;
    const ipv4 = addrs.filter(a => a.family === 'IPv4');
    if (ipv4.length > 0) {
      stats.push({
        name,
        address: ipv4[0].address,
        mac: ipv4[0].mac,
        internal: ipv4[0].internal
      });
    }
  }
  return stats;
}

function getSystemInfo() {
  const script = `
    $info = [PSCustomObject]@{
      hostname = $env:COMPUTERNAME;
      os = (Get-CimInstance Win32_OperatingSystem).Caption;
      osVersion = (Get-CimInstance Win32_OperatingSystem).Version;
      uptime = [math]::Floor((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty TotalSeconds);
      cpu = (Get-CimInstance Win32_Processor).Name;
      cpuUsage = (Get-CimInstance Win32_Processor).LoadPercentage;
      totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory;
      freeMemory = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB;
      processes = (Get-Process).Count;
      threads = (Get-Process | Measure-Object Threads -Sum).Sum;
      handles = (Get-Process | Measure-Object HandleCount -Sum).Sum
    };
    $info | ConvertTo-Json -Compress
  `;
  return runPowerShell(script);
}

function getBandwidthUsage() {
  const script = `
    $interfaces = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up';
    $result = @();
    foreach ($if in $interfaces) {
      $stats = Get-NetAdapterStatistics -Name $if.Name -ErrorAction SilentlyContinue;
      $result += [PSCustomObject]@{
        name = $if.Name;
        speed = $if.LinkSpeed;
        receivedBytes = if ($stats) { $stats.ReceivedBytes } else { 0 };
        sentBytes = if ($stats) { $stats.SentBytes } else { 0 };
      };
    };
    $result | ConvertTo-Json -Compress
  `;
  return runPowerShell(script);
}

function getArpTable() {
  try {
    const raw = execSync('arp -a', { encoding: 'utf8', timeout: 5000 });
    const entries = [];
    const lines = raw.split('\n');
    let currentInterface = '';
    for (const line of lines) {
      const ifaceMatch = line.match(/Interface:\s*([\d.]+)/);
      if (ifaceMatch) currentInterface = ifaceMatch[1];
      const entryMatch = line.match(/^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(dynamic|static)/i);
      if (entryMatch) {
        entries.push({
          IPAddress: entryMatch[1],
          LinkLayerAddress: entryMatch[2],
          State: entryMatch[3].charAt(0).toUpperCase() + entryMatch[3].slice(1),
          Interface: currentInterface
        });
      }
    }
    return entries;
  } catch { return []; }
}

function getDnsCache() {
  const script = `
    Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Name, Type, TimeToLive, DataLength | Sort-Object Entry | ConvertTo-Json -Compress
  `;
  return runPowerShell(script);
}

function getRoutingTable() {
  const script = `
    Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, Protocol | ConvertTo-Json -Compress
  `;
  return runPowerShell(script);
}

function validateSubnet(subnet) {
  const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/;
  const m = subnet.match(ipPattern);
  if (!m) throw new Error('Invalid subnet format. Use CIDR notation (e.g. 192.168.1.0/24)');
  for (let i = 1; i <= 4; i++) {
    const octet = parseInt(m[i], 10);
    if (octet < 0 || octet > 255) throw new Error('Invalid IP octet in subnet');
  }
  return m[1] + '.' + m[2] + '.' + m[3];
}

function scanNetwork(subnet) {
  const base = validateSubnet(subnet);
  try {
    const arpRaw = execSync('arp -a', { encoding: 'utf8', timeout: 5000 });
    const arpMap = {};
    for (const line of arpRaw.split('\n')) {
      const m = line.match(/^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(dynamic|static)/i);
      if (m && m[1].startsWith(base + '.')) arpMap[m[1]] = m[2];
    }
    const devices = Object.entries(arpMap).map(([ip, mac]) => ({
      ip, mac, hostname: '', status: 'online', source: 'arp'
    }));
    const script = `
      $base = "${base}";
      1..254 | ForEach-Object -Parallel {
        $ip = $using:base + "." + $_
        $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue;
        if ($ping) {
          try { $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $hostname = "" };
          [PSCustomObject]@{ ip = $ip; hostname = $hostname; status = "online" }
        }
      } -ThrottleLimit 100 | Where-Object { $_ -ne $null } | ConvertTo-Json -Compress
    `;
    try {
      const { spawnSync } = require('child_process');
      const child = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', timeout: 60000, maxBuffer: 10 * 1024 * 1024, windowsHide: true });
      if (child.error) throw child.error;
      const pinged = JSON.parse(child.stdout.trim());
      const arr = Array.isArray(pinged) ? pinged : [pinged];
      for (const p of arr) {
        const existing = devices.find(d => d.ip === p.ip);
        if (existing) existing.hostname = p.hostname || existing.hostname;
        else devices.push({ ip: p.ip, mac: arpMap[p.ip] || '', hostname: p.hostname || '', status: 'online', source: 'ping' });
      }
    } catch {}
    return devices.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  } catch { return []; }
}

module.exports = {
  getConnections, getOpenPorts, getProcessDetail,
  getNetworkInterfaces, getTrafficStats, getSystemInfo, getBandwidthUsage,
  getArpTable, getDnsCache, getRoutingTable, scanNetwork
};
