import React from 'react';

export default function AttackerProfile({ attacker }) {
  if (!attacker) return null;
  return (
    <div className="ai-section">
      <div className="ai-section-title">👤 Attacker Profile</div>
      <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{attacker.ip}</div>
      <div style={{ fontSize: '12px', color: '#888', marginTop: '8px' }}>
        First seen: {attacker.first_seen || '—'}<br />
        Last seen: {attacker.last_seen || '—'}<br />
        Attack types: {(attacker.attack_types || []).join(', ') || '—'}<br />
        Sessions: {(attacker.sessions || []).length}<br />
        Threat Score: {attacker.threat_score || 0}
      </div>
    </div>
  );
}
