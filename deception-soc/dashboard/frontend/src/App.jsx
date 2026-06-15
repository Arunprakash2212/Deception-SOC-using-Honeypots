import React, { useState, useEffect, useCallback } from 'react';

// ===========================================================================
// Configuration
// ===========================================================================
const API_BASE = '/api/dashboard';
const REFRESH_INTERVAL = 5000; // 5 seconds

// ===========================================================================
// Utility Functions
// ===========================================================================
function getScoreColor(score) {
  if (score >= 75) return '#ef4444';
  if (score >= 50) return '#f97316';
  if (score >= 25) return '#eab308';
  return '#22c55e';
}

function getSeverityColor(severity) {
  const map = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
  return map[severity] || '#888';
}

function formatTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return iso; }
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' +
           d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
}

function formatDuration(seconds) {
  if (!seconds || seconds <= 0) return '0s';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

// ===========================================================================
// Stat Card Component
// ===========================================================================
function StatCard({ icon, value, label, color }) {
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{ background: `${color}15`, color }}>
        {icon}
      </div>
      <div className="stat-info">
        <div className="stat-value" style={{ color }}>{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

// ===========================================================================
// Session Card Component
// ===========================================================================
function SessionCard({ session, isActive, onClick }) {
  const status = session.status || 'active';
  const badgeClass = status === 'active' ? 'badge-active' :
                     status === 'completed' ? 'badge-completed' : 'badge-expired';
  const typeLabel = (session.honeypot_type || session.service || session.attack_type || 'unknown').toUpperCase();
  const cmds = session.commands?.length || session.commands_executed?.length || 0;
  const creds = session.credentials_tried?.length || 0;

  return (
    <div className={`session-card ${isActive ? 'active' : ''}`} onClick={onClick}>
      <div className="session-card-header">
        <span className="session-ip">🎯 {session.attacker_ip}</span>
        <span className={`session-badge ${badgeClass}`}>{status}</span>
      </div>
      <div className="session-meta">
        <span>🏷️ {typeLabel}</span>
        <span>⌨️ {cmds} cmds</span>
        <span>🔑 {creds} creds</span>
        <span>⏱️ {formatDuration(session.duration_seconds)}</span>
      </div>
    </div>
  );
}

// ===========================================================================
// Terminal / Command Replay Component
// ===========================================================================
function CommandReplay({ commands }) {
  if (!commands || commands.length === 0) {
    return (
      <div className="terminal">
        <div className="terminal-header">
          <div className="terminal-dot" style={{ background: '#ef4444' }} />
          <div className="terminal-dot" style={{ background: '#eab308' }} />
          <div className="terminal-dot" style={{ background: '#22c55e' }} />
          <span className="terminal-title">Command Replay — No commands recorded</span>
        </div>
        <div className="terminal-body" style={{ color: '#555', textAlign: 'center', padding: '40px' }}>
          No commands captured in this session.
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
        <span className="terminal-title">admin@honeypot — Command Replay ({commands.length} commands)</span>
      </div>
      <div className="terminal-body">
        {commands.map((cmd, i) => {
          const command = typeof cmd === 'string' ? cmd : (cmd.command || cmd);
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

// ===========================================================================
// AI Analysis Component
// ===========================================================================
function AIAnalysis({ aiData }) {
  if (!aiData) {
    return (
      <div className="ai-section">
        <div className="ai-section-title">🧠 AI Analysis</div>
        <div style={{ color: '#555', fontSize: '13px' }}>
          Select a session to view AI classification and threat scoring.
        </div>
      </div>
    );
  }

  const threatScore = aiData.threat_score || {};
  const cluster = aiData.cluster || {};
  const score = threatScore.threat_score || 0;
  const severity = threatScore.severity || 'unknown';
  const reasons = threatScore.reasons || [];
  const clusterLabel = cluster.cluster_label || 'Unclassified';
  const confidence = cluster.confidence || 0;
  const scoreColor = getScoreColor(score);

  return (
    <div className="ai-section fade-in">
      <div className="ai-section-title">🧠 AI Analysis</div>
      <div className="threat-score-container">
        <div
          className="score-circle"
          style={{
            '--score-color': scoreColor,
            '--score-pct': score,
            color: scoreColor,
            background: `${scoreColor}10`,
            border: `2px solid ${scoreColor}30`,
          }}
        >
          {score}
          <div className="score-label" style={{ position: 'absolute', bottom: '-20px', color: '#888', width: '80px' }}>
            / 100
          </div>
        </div>
        <div className="score-details">
          <div className="score-severity" style={{ color: getSeverityColor(severity) }}>
            {severity} threat
          </div>
          <div className="cluster-info">
            Cluster: <span className="cluster-label">{clusterLabel}</span>
          </div>
          {confidence > 0 && (
            <>
              <div style={{ fontSize: '11px', color: '#888', marginBottom: '4px' }}>
                Confidence: {(confidence * 100).toFixed(1)}%
              </div>
              <div className="confidence-bar">
                <div className="confidence-fill" style={{ width: `${confidence * 100}%` }} />
              </div>
            </>
          )}
          {cluster.status === 'not_trained' && (
            <div style={{ fontSize: '11px', color: '#eab308', marginTop: '6px' }}>
              ⚠ AI model not yet trained — scoring is rule-based only
            </div>
          )}
        </div>
      </div>
      {reasons.length > 0 && (
        <ul className="reasons-list">
          {reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ===========================================================================
// Credential Stats Component
// ===========================================================================
function CredentialStats({ sessions }) {
  // Aggregate credentials from sessions
  const usernameCounts = {};
  const passwordCounts = {};

  (sessions || []).forEach(s => {
    const creds = s.credentials_tried || [];
    creds.forEach(c => {
      const u = c.username || 'unknown';
      const p = c.password || 'unknown';
      usernameCounts[u] = (usernameCounts[u] || 0) + 1;
      passwordCounts[p] = (passwordCounts[p] || 0) + 1;
    });
  });

  const topUsers = Object.entries(usernameCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const topPasswords = Object.entries(passwordCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);

  if (topUsers.length === 0 && topPasswords.length === 0) return null;

  return (
    <div className="ai-section">
      <div className="ai-section-title">🔑 Credential Analysis</div>
      <div className="cred-grid">
        <div>
          <table className="cred-table">
            <thead><tr><th>Username</th><th>Count</th></tr></thead>
            <tbody>
              {topUsers.map(([u, c], i) => (
                <tr key={i}><td>{u}</td><td style={{ color: 'var(--accent)' }}>{c}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <div>
          <table className="cred-table">
            <thead><tr><th>Password</th><th>Count</th></tr></thead>
            <tbody>
              {topPasswords.map(([p, c], i) => (
                <tr key={i}><td>{p}</td><td style={{ color: 'var(--accent)' }}>{c}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ===========================================================================
// Session Detail Component
// ===========================================================================
function SessionDetail({ session, aiData, commands }) {
  if (!session) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">🔍</div>
        <div className="empty-state-text">Select a session to view details</div>
      </div>
    );
  }

  const sessionCommands = commands || session.commands || [];
  const filesAccessed = session.files_accessed || [];
  const downloads = session.download_attempts || [];

  return (
    <div className="detail-content fade-in">
      {/* Session Info Bar */}
      <div className="ai-section" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div>
            <div style={{ fontSize: '18px', fontWeight: '700', color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
              {session.attacker_ip}
            </div>
            <div style={{ fontSize: '12px', color: '#888', marginTop: '4px' }}>
              {session.honeypot_type?.toUpperCase() || session.service?.toUpperCase() || 'UNKNOWN'} HONEYPOT
              {session.honeypot_ip && <span> — {session.honeypot_ip}:{session.honeypot_port}</span>}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '12px', color: '#888' }}>
              Started: {formatDate(session.session_start || session.start_time)}
            </div>
            <div style={{ fontSize: '12px', color: '#888' }}>
              Duration: {formatDuration(session.duration_seconds)}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '16px', fontSize: '12px' }}>
          <span style={{ color: '#22c55e' }}>⌨️ {sessionCommands.length} commands</span>
          <span style={{ color: '#eab308' }}>🔑 {(session.credentials_tried || []).length} credentials</span>
          <span style={{ color: '#3b82f6' }}>📁 {filesAccessed.length} files accessed</span>
          <span style={{ color: '#ef4444' }}>⬇️ {downloads.length} download attempts</span>
        </div>
      </div>

      {/* AI Analysis */}
      <AIAnalysis aiData={aiData} />

      {/* Command Replay */}
      <div style={{ marginBottom: '20px' }}>
        <CommandReplay commands={sessionCommands} />
      </div>

      {/* Files Accessed */}
      {filesAccessed.length > 0 && (
        <div className="ai-section">
          <div className="ai-section-title">📁 Files Accessed</div>
          <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
            {filesAccessed.map((f, i) => (
              <div key={i} style={{
                padding: '6px 0',
                borderBottom: '1px solid var(--border)',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                display: 'flex',
                justifyContent: 'space-between',
              }}>
                <span style={{ color: f.found ? '#22c55e' : '#ef4444' }}>
                  {f.found ? '✓' : '✗'} {f.path}
                </span>
                <span style={{ color: '#555' }}>{formatTime(f.timestamp)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// Main App Component
// ===========================================================================
export default function App() {
  const [overview, setOverview] = useState(null);
  const [allSessions, setAllSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionDetail, setSessionDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());

  // Fetch overview data
  const fetchOverview = useCallback(async () => {
    try {
      const resp = await fetch(`${API_BASE}/overview`);
      if (resp.ok) {
        const data = await resp.json();
        setOverview(data);
        // Combine active + completed sessions
        const sessions = [
          ...(data.active_sessions || []),
          ...(data.completed_sessions || []),
        ];
        setAllSessions(sessions);
      }
    } catch (err) {
      console.warn('Failed to fetch overview:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch session detail when a session is selected
  const fetchSessionDetail = useCallback(async (ip) => {
    try {
      const resp = await fetch(`${API_BASE}/session/${ip}`);
      if (resp.ok) {
        const data = await resp.json();
        setSessionDetail(data);
      }
    } catch (err) {
      console.warn('Failed to fetch session detail:', err);
    }
  }, []);

  // Auto-refresh
  useEffect(() => {
    fetchOverview();
    const interval = setInterval(fetchOverview, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchOverview]);

  // Clock
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Handle session selection
  const handleSessionClick = (session) => {
    setSelectedSession(session);
    setSessionDetail(null);
    if (session.attacker_ip) {
      fetchSessionDetail(session.attacker_ip);
    }
  };

  // Separate active and historical sessions
  const activeSessions = allSessions.filter(s => s.status === 'active');
  const historicalSessions = allSessions.filter(s => s.status !== 'active');

  const activeTraps = overview?.active_traps || activeSessions.length;
  const totalSessions = overview?.total_sessions || allSessions.length;
  const totalCommands = overview?.total_commands || 0;
  const totalCreds = overview?.total_credentials || 0;
  const trackedAttackers = overview?.tracked_attackers || 0;

  return (
    <div className="app">
      {/* ---- Header ---- */}
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
            {overview?.ai_model_trained ? '🧠 AI Ready' : '🧠 AI Untrained'}
          </div>
          <span className="header-time">
            {currentTime.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
        </div>
      </header>

      {/* ---- Stats Row ---- */}
      <div className="stats-row">
        <StatCard icon="🪤" value={activeTraps} label="Active Traps" color="#ef4444" />
        <StatCard icon="📊" value={totalSessions} label="Total Sessions" color="#3b82f6" />
        <StatCard icon="⌨️" value={totalCommands} label="Commands Captured" color="#22c55e" />
        <StatCard icon="🔑" value={totalCreds} label="Credentials Harvested" color="#eab308" />
        <StatCard icon="👤" value={trackedAttackers} label="Tracked Attackers" color="#a78bfa" />
      </div>

      {/* ---- Main Content ---- */}
      <div className="main-content">
        {/* Left Panel — Sessions List */}
        <div className="sessions-panel">
          <div className="panel-header">
            <div className="panel-title">
              🔴 Live Sessions
              <span className="count">{activeSessions.length}</span>
            </div>
          </div>

          <div className="sessions-list">
            {activeSessions.length > 0 ? (
              activeSessions.map((s, i) => (
                <SessionCard
                  key={`active-${i}`}
                  session={s}
                  isActive={selectedSession?.attacker_ip === s.attacker_ip && selectedSession?.status === 'active'}
                  onClick={() => handleSessionClick(s)}
                />
              ))
            ) : (
              <div style={{ padding: '30px 20px', textAlign: 'center', color: '#555', fontSize: '13px' }}>
                No active traps. Waiting for attackers...
                <div style={{ marginTop: '8px', fontSize: '20px', opacity: 0.3 }}>🕸️</div>
              </div>
            )}

            {historicalSessions.length > 0 && (
              <>
                <div className="section-divider">📜 Historical Sessions</div>
                {historicalSessions.map((s, i) => (
                  <SessionCard
                    key={`hist-${i}`}
                    session={s}
                    isActive={selectedSession?.attacker_ip === s.attacker_ip && selectedSession?.status !== 'active'}
                    onClick={() => handleSessionClick(s)}
                  />
                ))}
              </>
            )}
          </div>
        </div>

        {/* Right Panel — Detail */}
        <div className="detail-panel">
          {loading ? (
            <div className="empty-state">
              <div className="loading-spinner" />
              <div className="empty-state-text">Connecting to Deception-SOC services...</div>
            </div>
          ) : selectedSession ? (
            <SessionDetail
              session={selectedSession}
              aiData={sessionDetail?.ai_classification}
              commands={sessionDetail?.commands}
            />
          ) : (
            <div className="empty-state">
              <div className="empty-state-icon">🎭</div>
              <div className="empty-state-text" style={{ fontSize: '15px', fontWeight: '600' }}>
                Deception-SOC Dashboard
              </div>
              <div style={{ color: '#555', fontSize: '13px', maxWidth: '400px', textAlign: 'center', lineHeight: '1.6' }}>
                Select a session from the left panel to view attacker activity,
                AI classification, threat scoring, and full command replay.
              </div>
              <div style={{ display: 'flex', gap: '16px', marginTop: '20px' }}>
                <div style={{ textAlign: 'center', color: '#555', fontSize: '12px' }}>
                  <div style={{ fontSize: '24px', marginBottom: '4px' }}>🪤</div>
                  Honeypots
                </div>
                <div style={{ textAlign: 'center', color: '#555', fontSize: '12px' }}>
                  <div style={{ fontSize: '24px', marginBottom: '4px' }}>🧠</div>
                  AI Analysis
                </div>
                <div style={{ textAlign: 'center', color: '#555', fontSize: '12px' }}>
                  <div style={{ fontSize: '24px', marginBottom: '4px' }}>⌨️</div>
                  Command Replay
                </div>
                <div style={{ textAlign: 'center', color: '#555', fontSize: '12px' }}>
                  <div style={{ fontSize: '24px', marginBottom: '4px' }}>📊</div>
                  Threat Scoring
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
