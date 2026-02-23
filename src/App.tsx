import React, { useState, useEffect, useRef } from 'react';

const REAL_GOV_DOMAINS = [
  "cia.gov",
  "fbi.gov",
  "nasa.gov",
  "pentagon.mil",
  "defense.gov",
  "whitehouse.gov",
  "nsa.gov"
];

const RECON_LOG_TEMPLATES = [
  { log: "[INFO] Initializing Session for {DOMAIN} infiltration...", msg: "潜入セッション開始。暗号化トンネルを確立中。" },
  { log: "dig +short {DOMAIN} -> {IP}", msg: "DNSプロトコルからターゲットのIPアドレスを特定中。" },
  { log: "[INFO] Fetching DNS-over-HTTPS records from Google API...", msg: "Google DNS APIから詳細なDNSレコードを抽出中。" },
  { log: "{RAW_JSON}", msg: "受信した生データを解析。レコードの整合性を確認。" },
  { log: "whois {DOMAIN} | grep 'Registrant Organization'", msg: "WHOIS情報を照会。ドメインの登録組織を特定中。" },
  { log: "Registrant Organization: US Government Agency", msg: "登録組織が政府機関であることを確認。ターゲットを固定。" },
  { log: "subfinder -d {DOMAIN} -all -silent", msg: "サブドメインの列挙を実行。アタックサーフェスを拡張中。" },
  { log: "[FOUND] api.{DOMAIN}", msg: "APIゲートウェイを検出。バックエンドへの接続ポイントとして記録。" },
  { log: "[FOUND] dev.{DOMAIN}", msg: "開発環境を捕捉。構成不備の可能性を調査対象に追加。" },
  { log: "[FOUND] vpn.{DOMAIN}", msg: "VPNエンドポイントを捕捉。内部ネットワークへのバイパスを検討。" },
  { log: "[FOUND] secure-gateway.{DOMAIN}", msg: "認証ゲートウェイを特定。認証プロトコルの解析を開始。" },
  { log: "httpx -list subdomains.txt -status-code -title", msg: "各サブドメインの稼働状況とHTTPステータスを確認中。" },
  { log: "https://dev.{DOMAIN} [403] [Access Denied]", msg: "開発サーバーへのアクセス拒否を確認。WAFの存在を検知。" },
  { log: "https://api.{DOMAIN} [200] [API Gateway]", msg: "APIサーバーの応答を確認。侵入口としてマーク。" },
  { log: "https://secure-gateway.{DOMAIN} [200] [Enterprise Portal]", msg: "ポータルの稼働を確認。脆弱性調査リストに追加。" },
  { log: "[INFO] Detecting WAF (Web Application Firewall)...", msg: "防御製品（WAF）のベンダーとバージョンの特定を開始。" },
  { log: "wafw00f https://{DOMAIN}", msg: "WAFフィンガープリントを解析中。" },
  { log: "The site https://{DOMAIN} is behind Cloudflare WAF.", msg: "Cloudflareによる保護を確認。回避戦略を策定中。" },
  { log: "[SUCCESS] Phase 1: Reconnaissance complete. Target surface mapped.", msg: "フェーズ1：偵察完了。ターゲットのネットワークマップ作成に成功。" },
  { log: "Ready for Phase 2: Vulnerability Analysis.", msg: "準備完了。脆弱性診断フェーズへ移行。" }
];

const App: React.FC = () => {
  const [displayedLogs, setDisplayedLogs] = useState<string[]>([]);
  const [activeMessage, setActiveMessage] = useState<string>("Initializing hacker_os...");
  const [targetIP, setTargetIP] = useState<string>("0.0.0.0");
  const [rawJSON, setRawJSON] = useState<string>("{}");
  const [targetDomain] = useState(() => REAL_GOV_DOMAINS[Math.floor(Math.random() * REAL_GOV_DOMAINS.length)]);
  
  const [cpuLoad, setCpuLoad] = useState<number>(12.4);
  const [netTraffic, setNetTraffic] = useState<string>("240.5 MB/s");
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
      const speed = (Math.random() * 700 + 100).toFixed(1);
      setNetTraffic(`${speed} MB/s`);
      const diff = Date.now() - startTimeRef.current;
      const days = String(Math.floor(diff / 86400000)).padStart(2, '0');
      const hh = String(Math.floor((diff % 86400000) / 3600000)).padStart(2, '0');
      const mm = String(Math.floor((diff % 3600000) / 60000)).padStart(2, '0');
      const ss = String(Math.floor((diff % 60000) / 1000)).padStart(2, '0');
      setUptime(`${days}:${hh}:${mm}:${ss}`);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key.length > 1 && e.key !== 'Enter' && e.key !== 'Space' && e.key !== 'Backspace') return;
      keyCounterRef.current += 1;
      if (keyCounterRef.current >= KEYS_PER_LINE) {
        const currentIndex = logIndexRef.current;
        if (currentIndex < RECON_LOG_TEMPLATES.length) {
          const item = RECON_LOG_TEMPLATES[currentIndex];
          if (item.log === "{RAW_JSON}") {
            const jsonLines = rawJSON.split('\n');
            setDisplayedLogs(prev => [...prev, ...jsonLines]);
          } else {
            const logLine = item.log
              .replace(/{IP}/g, targetIP)
              .replace(/{DOMAIN}/g, targetDomain);
            setDisplayedLogs(prev => [...prev, logLine]);
          }
          setActiveMessage(item.msg);
          logIndexRef.current += 1;
        }
        keyCounterRef.current = 0;
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [targetIP, targetDomain, rawJSON]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [displayedLogs]);

  return (
    <div className="bg-black min-h-screen text-[#00ff41] flex overflow-hidden font-['JetBrains_Mono']">
      <div className="fixed inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] z-50"></div>
      
      {/* 左 2/3: ターミナルログ */}
      <div className="w-2/3 p-8 flex flex-col justify-start items-start select-text overflow-y-auto leading-none border-r border-[#00ff41]/20 scrollbar-hide">
        <div className="w-full max-w-7xl z-10 flex flex-col text-base md:text-lg pb-24 tracking-tighter">
          {displayedLogs.map((log, i) => (
            <div key={i} className="flex space-x-3 py-0">
              <span className="opacity-40 text-[11px] shrink-0 select-none mt-1 text-green-300">[{new Date().toLocaleTimeString()}]</span>
              <span className={`
                ${log.startsWith('[SUCCESS]') ? 'text-cyan-400 font-bold' : ''}
                ${log.startsWith('[INFO]') ? 'text-yellow-100 font-bold' : ''}
                ${log.startsWith('[FOUND]') ? 'text-blue-300' : ''}
                ${log.includes('[200]') ? 'text-green-300 font-semibold' : ''}
                ${log.includes('[403]') ? 'text-red-400' : ''}
                ${log.trim().startsWith('"') || log.trim().startsWith('{') || log.trim().startsWith('}') || log.trim().startsWith(']') ? 'text-gray-500 text-sm opacity-70 whitespace-pre leading-none' : ''}
              `}>
                {log}
              </span>
            </div>
          ))}
          <div className="flex items-center space-x-4 pt-3">
            <span className="text-[#00ff41] font-bold shrink-0 opacity-80 select-none">root@hacker_os:~#</span>
            <div className="flex flex-col">
              <span className="w-2.5 h-5 bg-[#00ff41] animate-pulse shrink-0"></span>
            </div>
          </div>
          <div ref={bottomRef} />
        </div>
      </div>

      {/* 右 1/3: システムメッセージ（日本語） */}
      <div className="w-1/3 bg-[#001100] p-10 flex flex-col z-20 shadow-[-10px_0_30px_rgba(0,0,0,0.5)] border-l border-[#00ff41]/10">
        <div className="mb-8 border-b border-[#00ff41]/30 pb-4">
          <h2 className="text-xs uppercase tracking-widest opacity-50 mb-2 font-sans font-bold text-[#00ff41]">System Narrative Monitor</h2>
          <div className="text-cyan-400 font-bold text-sm uppercase tracking-tighter">ACTIVE PHASE: RECONNAISSANCE</div>
        </div>

        <div className="flex-1 flex flex-col justify-center">
          <div className="bg-[#002200] border-l-4 border-green-500 p-6 shadow-[0_0_20px_rgba(0,255,0,0.1)]">
            <p className="text-green-100 text-lg md:text-xl leading-relaxed animate-fade-in font-sans">
              {activeMessage}
            </p>
          </div>
        </div>

        <div className="mt-8 opacity-30 text-[10px] space-y-2 font-mono border-t border-[#00ff41]/10 pt-4">
          <div className="flex justify-between items-center text-[#00ff41]">
            <span>CPU LOAD:</span>
            <div className="flex items-baseline space-x-1">
              <span className="text-white font-bold">{cpuLoad.toFixed(1)}</span>
              <span className="text-[8px] opacity-70">%</span>
            </div>
          </div>
          <div className="flex justify-between items-center text-[#00ff41]">
            <span>NET TRAFFIC:</span>
            <span className="text-white font-bold">{netTraffic}</span>
          </div>
          <div className="flex justify-between items-center text-[#00ff41]">
            <span>SESSION UPTIME:</span>
            <span className="text-white font-bold">{uptime}</span>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(5px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fade-in {
          animation: fadeIn 0.3s ease-out;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
        .animate-pulse {
          animation: pulse 1s step-end infinite;
        }
        ::selection {
          background-color: #00ff41;
          color: black;
        }
        .scrollbar-hide::-webkit-scrollbar {
          display: none;
        }
        .scrollbar-hide {
          -ms-overflow-style: none;
          scrollbar-width: none;
        }
      `}</style>
    </div>
  );
};

export default App;
