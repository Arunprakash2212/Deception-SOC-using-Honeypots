import React from 'react';

export default function SessionDetail({ session }) {
  if (!session) return null;
  return (
    <div className="ai-section">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontSize: '18px', fontWeight: '700', color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
            {session.attacker_ip}
          </div>
          <div style={{ fontSize: '12px', color: '#888', marginTop: '4px' }}>
            {(session.honeypot_type || session.service || 'unknown').toUpperCase()} HONEYPOT
          </div>
        </div>
      </div>
    </div>
  );
}
