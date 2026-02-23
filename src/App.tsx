import React, { useState, useEffect } from 'react';

const App: React.FC = () => {
  return (
    <div className="bg-black min-h-screen text-[#00ff41] font-mono p-8 flex flex-col justify-start items-start overflow-hidden select-none">
      {/* 画面上のスキャンライン（ノイズ）エフェクト */}
      <div className="fixed inset-0 pointer-events-none opacity-10 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%]"></div>
      
      <div className="w-full max-w-7xl z-10 flex flex-col">
        <div className="flex items-center space-x-4 text-xl md:text-2xl">
          <span className="text-[#00ff41] font-bold shrink-0 opacity-80">root@hacker_os:~#</span>
          <div className="flex flex-col">
            <span className="w-3 h-7 bg-[#00ff41] animate-pulse shrink-0"></span>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
        .animate-pulse {
          animation: pulse 1s step-end infinite;
        }
      `}</style>
    </div>
  );
};

export default App;
