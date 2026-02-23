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
  const nodes = [
    "NY-FIN-WALL-STREET", "LONDON-EXCH-CITY", "TOKYO-STOCK-KABUTOCHO", "SINGAPORE-FIN-RAFFLES", "HK-EXCH-CENTRAL", "FRANKFURT-EXCH-BOERSE", "ZURICH-BANKING-CRYPT",
    "US-EAST-PWR-GRID", "US-WEST-PWR-GRID", "EU-CENTRAL-PWR-SYNC", "CHINA-THREE-GORGES-CTRL", "RUSSIA-GAZPROM-FLOW", "FRENCH-NUC-GRAVELINES", "JAPAN-FUKUSHIMA-SEC",
    "TEXAS-ERCOT-LOAD-BAL", "DUBAI-WATER-DESAL-PLANT", "NORAD-EARLY-WARNING", "PENTAGON-SECURE-CORE", "NATO-COMMAND-BRUSSELS", "STRATCOM-GLOBAL-STRIKE",
    "KREMLIN-SECURE-COM", "MOSSAD-INTEL-LINK", "PACIFIC-FLEET-PEARL-HARBOR", "ATLANTIC-FLEET-NORFOLK", "UK-MOD-WHITEHALL", "IDF-IRON-DOME-CTRL", "JFK-AIR-TRAFFIC-CTRL",
    "HEATHROW-ATC-RADAR", "HANEDA-GROUND-LOGIC", "CHANGI-AUTO-TERMINAL", "DUBAI-INTL-LOGISTICS", "SUEZ-CANAL-TRAFFIC-MGMT", "PANAMA-CANAL-LOCK-SYS",
    "ROTTERDAM-PORT-AUTOMATION", "SHANGHAI-CONTAINER-TERM", "STARLINK-ORBIT-G12", "GPS-III-CONSTELLATION", "GALILEO-GNSS-SAT", "GLONASS-SECURE-BEAM",
    "NASA-DSN-GOLDSTONE", "ESA-ESTEC-TRACKING", "JAXA-TANEGASHIMA-LNK", "GLOBAL-DNS-ROOT-A-VERISIGN", "GLOBAL-DNS-ROOT-K-RIPE", "ICANN-IANA-SEC-DNS",
    "ATLANTIC-FIBER-TAT14", "PACIFIC-CABLE-UNITY", "INDIGO-SUBSEA-CABLE", "BGP-ASHBURN-IXP", "BGP-AMSTERDAM-AMS-IX", "AWS-REGION-US-EAST-1",
    "AWS-REGION-AP-NORTHEAST-1", "GCP-ASIA-SOUTH-1", "AZURE-EUROPE-WEST", "CLOUDFLARE-EDGE-CHICAGO", "AKAMAI-CDN-PARIS", "GOOGLE-DNS-8.8.8.8",
    "QUAD9-DNS-9.9.9.9", "CERN-LHC-DATA-GRID", "ITER-FUSION-STABILITY-CTRL", "WHO-PANDEMIC-WARN-NET", "INTERPOL-GLOBAL-SEARCH", "UN-SECURE-VOTING-NET",
    "APPLE-ICLOUD-SYNC-DC", "META-PROD-SERVER-OR", "SAUDI-ARAMCO-DATA-VAULT", "BP-OIL-PLATFORM-CTRL", "SHELL-DEEPWATER-DRIL", "SAMSUNG-SEMICON-FAB",
    "TSMC-NANOFAB-HSINCHU", "VW-AUTO-LOGI-WOLFSBURG", "TESLA-GIGA-BERLIN-GRID", "RIO-TINTO-AUTONOMOUS-MINING", "MAERSK-LOGISTICS-TRACKING",
    "FEDEX-GLOBAL-SORT-MEMPHIS", "DHL-EURO-HUB-LEIPZIG", "UPS-WORLDPORT-LOUISVILLE", "AUSTRALIA-PWR-NEM", "BRAZIL-ITAIPU-HYDRO", "EGYPT-ASWAN-DAM-CTRL",
    "INDIA-NATIONAL-GRID-DELHI", "MEXICO-TELMEX-BACKBONE", "NIGERIA-OIL-EXCH-LAGOS", "SOUTH-AFRICA-ESKOM-GRID", "SINGAPORE-MARINA-DESAL",
    "NETHERLANDS-MAESLANTKERING-CTRL", "VENICE-MOSE-BARRIER-SYS", "SCANDINAVIA-ARCTIC-FIBER", "ANTARCTICA-MCMURDO-COM", "ORBITAL-ISS-COMM-RELAY",
    "DEEP-SEA-RESEARCH-VDS", "CRYPTO-BTC-MINING-KAZ", "ETH-STAKING-VAULT-AWS", "SWIFT-PAYMENT-GW-INT", "VISA-TRANSACTION-CORE", "MASTERCARD-CLEARING-SYS",
    "EBAY-TX-DATABASE", "AMAZON-FULFILLMENT-NET", "UBER-REALTIME-FLEET", "GOVERNMENT-EMERGENCY-EAS"
  ];
  const logs: string[] = [];
  const now = new Date();
  const month = now.toLocaleString('en-US', { month: 'short' });
  const day = now.getDate();
  const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
  const dateStr = `${month} ${day}`;

  nodes.forEach(node => {
    const pid = Math.floor(Math.random() * 900000 + 100000);
    const mem = (Math.random() * 500 + 10).toFixed(1);
    const cpu = (Math.random() * 100).toFixed(3);
    const uptime = `${Math.floor(Math.random() * 12 + 1)} months ${Math.floor(Math.random() * 28)} days`;
    
    logs.push(`● AEGIS-${node}.service - AEGIS National Security Node`);
    logs.push(`     Loaded: loaded (/usr/lib/systemd/system/aegis.service; enabled; preset: enabled)`);
    logs.push(`     Active: deactivating (stop-sigterm) since Mon ${dateStr} ${timeStr} UTC; ${uptime} ago`);
    logs.push(`   Main PID: ${pid} (aegis-core)`);
    logs.push(`      Tasks: ${Math.floor(Math.random() * 20 + 1)} (limit: 18707)`);
    logs.push(`     Memory: ${mem}M (peak: ${mem}M)`);
    logs.push(`        CPU: ${cpu}s`);
    logs.push(`     CGroup: /system.slice/AEGIS-${node}.service`);
    logs.push(`             └─${pid} "/usr/bin/aegis-core --node-id ${node} --magic 0xDEADBEEF"`);
    logs.push(`${dateStr} ${timeStr} node-server aegis-core[${pid}]: Received magic packet 0xDEADBEEF. Triggering shutdown.`);
    logs.push(`${dateStr} ${timeStr} node-server systemd[1]: Stopped AEGIS-${node}.service.`);
    logs.push(`[  OK  ] Stopped AEGIS-${node}.service.`);
    logs.push(""); // Spacer
  });
  
  logs.push("[  OK  ] System-wide HALT state achieved.");
  logs.push("[  OK  ] All grid status: OFFLINE.");
  return logs;
})();
