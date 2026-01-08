
import React from 'react';
import { SecurityEvent } from '../types';

interface SecurityDashboardProps {
  logs: SecurityEvent[];
}

export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({ logs }) => {
  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center justify-between mb-10">
        <h2 className="font-black text-[12px] text-black uppercase tracking-[0.3em]">Protocol Audit</h2>
        <div className="flex gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-blue-500"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-slate-200"></div>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto space-y-5 scrollbar-hide">
        {logs.map((log) => (
          <div key={log.id} className={`p-5 rounded-3xl border-l-8 bg-slate-50 transition-all hover:shadow-md ${
            log.status === 'SUCCESS' ? 'border-blue-600' : 'border-red-600'
          }`}>
            <div className="flex justify-between items-center mb-3">
              <span className={`text-[10px] font-black uppercase tracking-widest ${
                log.status === 'SUCCESS' ? 'text-blue-700' : 'text-red-700'
              }`}>
                [{log.type}]
              </span>
              <span className="text-[10px] font-black text-slate-400">{new Date(log.timestamp).toLocaleTimeString([], { hour12: false })}</span>
            </div>
            <p className="text-[11px] text-black font-black leading-relaxed uppercase tracking-tight">{log.message}</p>
          </div>
        ))}
        {logs.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center border-4 border-dashed border-slate-50 rounded-[3rem] p-10 text-center">
            <i className="fas fa-radar text-slate-100 text-6xl mb-6"></i>
            <p className="text-[11px] text-slate-300 font-black uppercase tracking-[0.2em]">Passive Monitoring Active</p>
          </div>
        )}
      </div>
      
      <div className="mt-10 pt-10 border-t border-slate-100 space-y-6">
        <div className="p-6 bg-slate-50 rounded-[2rem] border border-slate-200">
          <div className="flex justify-between text-[11px] font-black uppercase tracking-widest text-black mb-4 border-b border-slate-200 pb-3">
            <span>Cryptographic Stack</span>
            <span className="text-blue-600">TLS 1.3+</span>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between text-[10px] font-black uppercase tracking-widest text-slate-500">
              <span>Block Cipher</span>
              <span className="text-black">AES-256-GCM</span>
            </div>
            <div className="flex justify-between text-[10px] font-black uppercase tracking-widest text-slate-500">
              <span>Handshake</span>
              <span className="text-black">RSA-2048</span>
            </div>
            <div className="flex justify-between text-[10px] font-black uppercase tracking-widest text-slate-500">
              <span>Derivation</span>
              <span className="text-black">PBKDF2</span>
            </div>
          </div>
        </div>
        
        <div className="flex items-center gap-4 p-4 bg-blue-50 border border-blue-100 rounded-2xl">
           <i className="fas fa-shield-virus text-blue-600 text-lg"></i>
           <p className="text-[10px] text-blue-800 font-black uppercase tracking-tight leading-tight">Zero-Knowledge Storage: Private keys are derived locally.</p>
        </div>
      </div>
    </div>
  );
};
