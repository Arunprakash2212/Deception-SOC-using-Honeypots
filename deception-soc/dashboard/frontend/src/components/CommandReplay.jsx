import React from 'react';

function formatTime(iso) {
  if (!iso) return '';
  try { return new Date(iso).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  catch { return iso; }
}

export default function CommandReplay({ commands }) {
  if (!commands || commands.length === 0) {
    return (
      <div className="terminal">
        <div className="terminal-header">
          <div className="terminal-dot" style={{ background: '#ef4444' }} />
          <div className="terminal-dot" style={{ background: '#eab308' }} />
          <div className="terminal-dot" style={{ background: '#22c55e' }} />
          <span className="terminal-title">Command Replay — No commands</span>
        </div>
        <div className="terminal-body" style={{ color: '#555', textAlign: 'center', padding: '40px' }}>
          No commands captured.
        </div>
      </div>
    );
  }
  return (
    <div className="terminal">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: '#ef4444' }} />
        <div className="terminal-dot" style={{ background: '#eab308' }} />
        <div className="terminal-dot" style={{ background: '#22c55e' }} />
        <span className="terminal-title">admin@honeypot — {commands.length} commands</span>
      </div>
      <div className="terminal-body">
        {commands.map((cmd, i) => {
          const command = typeof cmd === 'string' ? cmd : (cmd.command || '');
          const ts = cmd.timestamp ? formatTime(cmd.timestamp) : '';
          const cwd = cmd.cwd || '~';
          return (
            <div key={i} className="cmd-line">
              <span className="cmd-prompt">admin@honeypot:{cwd}$</span>
              <span className="cmd-text">{command}</span>
              {ts && <span className="cmd-time">{ts}</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
}
