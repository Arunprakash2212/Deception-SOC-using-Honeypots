import React from 'react';

export default function CredentialStats({ credentials }) {
  const { top_usernames = [], top_passwords = [] } = credentials || {};
  if (top_usernames.length === 0 && top_passwords.length === 0) {
    return (
      <div className="ai-section">
        <div className="ai-section-title">🔑 Credential Stats</div>
        <div style={{ color: '#555', fontSize: '13px' }}>No credentials harvested yet.</div>
      </div>
    );
  }
  return (
    <div className="ai-section">
      <div className="ai-section-title">🔑 Top Credentials</div>
      <div className="cred-grid">
        <div>
          <table className="cred-table">
            <thead><tr><th>Username</th><th>Count</th></tr></thead>
            <tbody>
              {top_usernames.map((u, i) => (
                <tr key={i}><td>{u.username}</td><td style={{ color: 'var(--accent)' }}>{u.count}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <div>
          <table className="cred-table">
            <thead><tr><th>Password</th><th>Count</th></tr></thead>
            <tbody>
              {top_passwords.map((p, i) => (
                <tr key={i}><td>{p.password}</td><td style={{ color: 'var(--accent)' }}>{p.count}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
