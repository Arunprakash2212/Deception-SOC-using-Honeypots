import React from 'react';

function formatDuration(seconds) {
  if (!seconds || seconds <= 0) return '0s';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

export default function LiveSessions({ sessions, selectedIp, onSelect }) {
  const active = sessions.filter(s => s.status === 'active');
  const historical = sessions.filter(s => s.status !== 'active');

  return (
    <div className="sessions-panel">
      <div className="panel-header">
        <div className="panel-title">
          🔴 Live Sessions <span className="count">{active.length}</span>
        </div>
      </div>
      <div className="sessions-list">
        {active.length > 0 ? active.map((s, i) => (
          <div key={`a-${i}`}
               className={`session-card ${selectedIp === s.attacker_ip ? 'active' : ''}`}
               onClick={() => onSelect(s)}>
            <div className="session-card-header">
              <span className="session-ip">🎯 {s.attacker_ip}</span>
              <span className="session-badge badge-active">active</span>
            </div>
            <div className="session-meta">
              <span>🏷️ {(s.honeypot_type || s.attack_type || 'unknown').toUpperCase()}</span>
              <span>⌨️ {(s.commands || []).length} cmds</span>
              <span>⏱️ {formatDuration(s.duration_seconds)}</span>
            </div>
          </div>
        )) : (
          <div style={{ padding: '30px 20px', textAlign: 'center', color: '#555', fontSize: '13px' }}>
            No active traps. Waiting for attackers... 🕸️
          </div>
        )}
        {historical.length > 0 && (
          <>
            <div className="section-divider">📜 Historical Sessions</div>
            {historical.map((s, i) => (
              <div key={`h-${i}`}
                   className={`session-card ${selectedIp === s.attacker_ip ? 'active' : ''}`}
                   onClick={() => onSelect(s)}>
                <div className="session-card-header">
                  <span className="session-ip">🎯 {s.attacker_ip}</span>
                  <span className={`session-badge ${s.status === 'completed' ? 'badge-completed' : 'badge-expired'}`}>
                    {s.status}
                  </span>
                </div>
                <div className="session-meta">
                  <span>🏷️ {(s.honeypot_type || 'unknown').toUpperCase()}</span>
                  <span>⌨️ {(s.commands || []).length} cmds</span>
                </div>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
