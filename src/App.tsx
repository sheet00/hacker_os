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
  "[INFO] Initializing Session for {DOMAIN} infiltration...",
  "dig +short {DOMAIN} -> {IP}",
  "[INFO] Fetching DNS-over-HTTPS records from Google API...",
  "{RAW_JSON}",
  "whois {DOMAIN} | grep 'Registrant Organization'",
  "Registrant Organization: US Government Agency",
  "subfinder -d {DOMAIN} -all -silent",
  "[FOUND] api.{DOMAIN}",
  "[FOUND] dev.{DOMAIN}",
  "[FOUND] vpn.{DOMAIN}",
  "[FOUND] secure-gateway.{DOMAIN}",
  "httpx -list subdomains.txt -status-code -title",
  "https://dev.{DOMAIN} [403] [Access Denied]",
  "https://api.{DOMAIN} [200] [API Gateway]",
  "https://secure-gateway.{DOMAIN} [200] [Enterprise Portal]",
  "[INFO] Detecting WAF (Web Application Firewall)...",
  "wafw00f https://{DOMAIN}",
  "The site https://{DOMAIN} is behind Cloudflare WAF.",
  "[SUCCESS] Phase 1: Reconnaissance complete. Target surface mapped.",
  "Ready for Phase 2: Vulnerability Analysis."
];

const App: React.FC = () => {
  const [displayedLogs, setDisplayedLogs] = useState<string[]>([]);
  const [logIndex, setLogIndex] = useState(0);
  const [targetIP, setTargetIP] = useState<string>("0.0.0.0");
  const [rawJSON, setRawJSON] = useState<string>("{}");
  const [targetDomain] = useState(() => REAL_GOV_DOMAINS[Math.floor(Math.random() * REAL_GOV_DOMAINS.length)]);
  const bottomRef = useRef<HTMLDivElement>(null);

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
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key.length > 1 && e.key !== 'Enter' && e.key !== 'Space' && e.key !== 'Backspace') return;

      if (logIndex < RECON_LOG_TEMPLATES.length) {
        if (RECON_LOG_TEMPLATES[logIndex] === "{RAW_JSON}") {
          const jsonLines = rawJSON.split('\n');
          setDisplayedLogs(prev => [...prev, ...jsonLines]);
        } else {
          const logLine = RECON_LOG_TEMPLATES[logIndex]
            .replace(/{IP}/g, targetIP)
            .replace(/{DOMAIN}/g, targetDomain);
          setDisplayedLogs(prev => [...prev, logLine]);
        }
        setLogIndex(prev => prev + 1);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [logIndex, targetIP, targetDomain, rawJSON]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [displayedLogs]);

  return (
    <div className="bg-black min-h-screen text-[#00ff41] p-8 flex flex-col justify-start items-start select-text overflow-y-auto leading-none font-['JetBrains_Mono']">
      <div className="fixed inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] z-50"></div>
      
      <div className="w-full max-w-7xl z-10 flex flex-col text-base md:text-lg pb-24 tracking-tighter">
        {displayedLogs.map((log, i) => (
          <div key={i} className="flex space-x-2 py-0">
            <span className="opacity-10 text-[9px] shrink-0 select-none mt-1">[{new Date().toLocaleTimeString()}]</span>
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

      <style>{`
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
        ::-webkit-scrollbar {
          width: 6px;
        }
        ::-webkit-scrollbar-track {
          background: #000;
        }
        ::-webkit-scrollbar-thumb {
          background: #002211;
          border-radius: 3px;
        }
        ::-webkit-scrollbar-thumb:hover {
          background: #00ff41;
        }
      `}</style>
    </div>
  );
};

export default App;
