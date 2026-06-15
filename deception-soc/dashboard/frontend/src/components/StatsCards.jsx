import React from 'react';

export default function StatsCards({ stats }) {
  const cards = [
    { icon: '🪤', value: stats.activeTraps || 0, label: 'Active Traps', color: '#ef4444' },
    { icon: '📊', value: stats.totalSessions || 0, label: 'Total Sessions', color: '#3b82f6' },
    { icon: '⌨️', value: stats.totalCommands || 0, label: 'Commands Captured', color: '#22c55e' },
    { icon: '🔑', value: stats.totalCredentials || 0, label: 'Credentials Harvested', color: '#eab308' },
    { icon: '👤', value: stats.trackedAttackers || 0, label: 'Tracked Attackers', color: '#a78bfa' },
  ];

  return (
    <div className="stats-row">
      {cards.map((card, i) => (
        <div key={i} className="stat-card">
          <div className="stat-icon" style={{ background: `${card.color}15`, color: card.color }}>
            {card.icon}
          </div>
          <div className="stat-info">
            <div className="stat-value" style={{ color: card.color }}>{card.value}</div>
            <div className="stat-label">{card.label}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
