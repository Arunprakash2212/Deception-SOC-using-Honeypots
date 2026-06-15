import React from 'react';

export default function Navbar({ activeTraps, aiTrained, currentTime }) {
  return (
    <header className="header">
      <div className="header-left">
        <span className="header-logo">🎭</span>
        <span className="header-title">Deception-Driven SOC</span>
      </div>
      <div className="header-right">
        <div className="header-badge">
          <div className="pulse-dot" />
          {activeTraps} Active Traps
        </div>
        <div className="header-badge" style={{ background: 'rgba(83,52,131,0.15)', borderColor: 'rgba(83,52,131,0.3)', color: '#a78bfa' }}>
          {aiTrained ? '🧠 AI Ready' : '🧠 AI Untrained'}
        </div>
        <span className="header-time">
          {currentTime.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </span>
      </div>
    </header>
  );
}
