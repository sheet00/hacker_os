export const REAL_CVE_DATABASE = [
  "[FOUND] CVE-2021-44228 - CVSS: 10.0 - Apache Log4j2 JNDI Remote Code Execution",
  "[FOUND] CVE-2021-41773 - CVSS: 7.5 - Apache HTTP Server path traversal and file disclosure",
  "[FOUND] CVE-2014-0160 - CVSS: 5.0 - OpenSSL Heartbleed information disclosure",
  "[FOUND] CVE-2014-6271 - CVSS: 10.0 - Bash Shellshock Remote Code Execution",
  "[FOUND] CVE-2019-11043 - CVSS: 9.8 - PHP-FPM Remote Code Execution in nginx configuration",
  "[FOUND] CVE-2020-1472 - CVSS: 10.0 - Microsoft Active Directory Netlogon (Zerologon)",
  "[FOUND] CVE-2021-4034 - CVSS: 7.8 - Polkit Pkexec Local Privilege Escalation (PwnKit)",
  "[FOUND] CVE-2022-0847 - CVSS: 7.8 - Linux Kernel Dirty Pipe Local Privilege Escalation",
  "[FOUND] CVE-2017-0144 - CVSS: 8.1 - Windows SMB Remote Code Execution (EternalBlue)",
  "[FOUND] CVE-2021-26855 - CVSS: 9.8 - Microsoft Exchange Server SSRF (ProxyLogon)",
  "[FOUND] CVE-2023-4911 - CVSS: 7.8 - GNU C Library ld.so buffer overflow (Looney Tunables)",
  "[FOUND] CVE-2024-3094 - CVSS: 10.0 - XZ Utils backdoor in liblzma",
  "[FOUND] CVE-2018-13379 - CVSS: 9.8 - Fortinet FortiOS SSL VPN credential disclosure",
  "[FOUND] CVE-2019-19781 - CVSS: 9.8 - Citrix ADC and Gateway Remote Code Execution",
  "[FOUND] CVE-2020-0601 - CVSS: 5.4 - Windows CryptoAPI spoofing (CurveBall)",
];

export const AUTO_LOGS: string[] = (() => {
  const l = [
    "[INFO] CI/CD Pipeline #842 triggered",
    "[INFO] Pulling container image...",
    "[INFO] Step 1/12: Code Checkout",
  ];
  for (let i = 1; i <= 5; i++)
    l.push(`[BUILD] Compiling module [${i}/20]: src/core/mod_${i}.c ... DONE`);
  for (let i = 1; i <= 5; i++)
    l.push(`[TEST] Test Case #${i.toString().padStart(3, "0")}: PASSED`);
  l.push("[INFO] Step 9/12: Digital Signature Verification");
  l.push("[INFO] Step 12/12: Production Rollout");
  for (let i = 1; i <= 5; i++)
    l.push(`[DEPLOY] Updating Node [AEGIS-PROD-NODE-0${i}] ... 100%`);
  for (let i = 1; i <= 5; i++) l.push(`[CHECK] AEGIS-PROD-NODE-0${i}: HEALTHY`);
  l.push("[INFO] Verification: Signal status ... SILENCED");
  l.push(
    "[SUCCESS] Deployment complete. AEGIS-ARMOR v4.2.1-patched is now live.",
  );
  return l;
})();

export const SHUTDOWN_LOGS: string[] = (() => {
  const nodeDefs = [
    { id: "NY-WALL-STREET", svc: "financial-tx-engine", ip: "104.16.148.21" },
    { id: "LONDON-CITY", svc: "settlement-gateway", ip: "212.58.244.70" },
    { id: "TOKYO-KABUTOCHO", svc: "exchange-matching-core", ip: "133.242.10.33" },
    { id: "US-EAST-GRID", svc: "scada-grid-balancer", ip: "198.51.100.50" },
    { id: "US-WEST-GRID", svc: "load-distribution-sys", ip: "10.3.5.8" },
    { id: "NORAD-HQ", svc: "early-warning-radar", ip: "10.5.12.3" },
    { id: "PENTAGON-CORE", svc: "c4i-strategic-net", ip: "10.1.0.12" },
    { id: "SWIFT-NETWORK", svc: "swift-payment-router", ip: "151.101.1.1" },
    { id: "ROOT-DNS-SERVER", svc: "dns-anycast-daemon", ip: "199.7.83.42" },
    { id: "JFK-AIR-TRAFFIC", svc: "atc-radar-processor", ip: "204.79.197.200" },
    { id: "GPS-CONSTELLATION", svc: "gnss-telemetry-link", ip: "172.16.1.1" },
    { id: "SUEZ-CANAL-TRAFFIC", svc: "vessel-traffic-mgmt", ip: "192.168.2.1" },
    { id: "FRENCH-NUC-PLANT", svc: "reactor-cooling-logic", ip: "10.6.1.1" },
    { id: "AWS-CORE-EAST", svc: "ebs-storage-controller", ip: "52.216.0.1" },
    { id: "CLOUDFLARE-EDGE", svc: "waf-filter-engine", ip: "104.17.210.9" }
  ];

  const nodes: { id: string, svc: string, ip: string }[] = [...nodeDefs];
  const genericSvcs = ["packet-inspector", "encrypted-tunnel", "secure-vault-io", "signal-relay", "auth-validator"];
  
  while (nodes.length < 100) {
    const r1 = Math.floor(Math.random() * 254) + 1;
    const nodeID = `EXT-NODE-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;
    const svcName = genericSvcs[Math.floor(Math.random() * genericSvcs.length)];
    nodes.push({ id: nodeID, svc: svcName, ip: `192.0.2.${r1}` });
  }

  const logs: string[] = [];
  const now = new Date();
  const month = now.toLocaleString('en-US', { month: 'short' });
  const day = now.getDate();
  const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
  const dateStr = `${month} ${day}`;

  nodes.forEach(node => {
    const pid = Math.floor(Math.random() * 900000 + 100000);
    const mem = (Math.random() * 500 + 10).toFixed(1);
    
    logs.push(`[SEND] 0xDEADBEEF -> ${node.ip}:5555 (Encrypted Payload)`);
    logs.push(`[RECV] ${node.ip}: ACK_RECEIVED (Triggering Local Shutdown)`);
    logs.push(`Stopping dependent: aegis-proxy.service...`);
    logs.push(`[  OK  ] Stopped aegis-proxy.service.`);
    
    logs.push(`● ${node.svc}.service - AEGIS Modern Security Service`);
    logs.push(`     Loaded: loaded (/usr/lib/systemd/system/${node.svc}.service; enabled)`);
    logs.push(`     Active: deactivating (stop-sigterm) since Mon ${dateStr} ${timeStr} UTC`);
    logs.push(`   Main PID: ${pid} (${node.svc})`);
    logs.push(`     CGroup: /system.slice/${node.svc}.service`);
    logs.push(`             └─${pid} "/usr/bin/${node.svc} --magic 0xDEADBEEF"`);
    
    logs.push(`${dateStr} ${timeStr} node-server ${node.svc}[${pid}]: Magic packet detected. Shutdown initiated.`);
    logs.push(`${dateStr} ${timeStr} node-server systemd[1]: Stopped ${node.svc}.service.`);
    logs.push(`[  OK  ] Finalized: ${node.svc}.service`);
    logs.push(`----------------------------------------------------------------`);
  });
  
  logs.push("[  OK  ] Global termination sequence finalized.");
  logs.push("[  OK  ] All grid status: OFFLINE.");
  return logs;
})();
