import React from 'react';

function getScoreColor(score) {
  if (score >= 75) return '#ef4444';
  if (score >= 50) return '#f97316';
  if (score >= 25) return '#eab308';
  return '#22c55e';
}

export default function ThreatScore({ scoreData }) {
  if (!scoreData) return null;
  const score = scoreData.threat_score || 0;
  const severity = scoreData.severity || 'unknown';
  const reasons = scoreData.reasons || [];
  const color = getScoreColor(score);

  return (
    <div className="ai-section">
      <div className="ai-section-title">⚡ Threat Score</div>
      <div className="threat-score-container">
        <div className="score-circle" style={{ '--score-color': color, '--score-pct': score, color, background: `${color}10`, border: `2px solid ${color}30` }}>
          {score}
        </div>
        <div className="score-details">
          <div className="score-severity" style={{ color }}>{severity.toUpperCase()}</div>
          {reasons.length > 0 && (
            <ul className="reasons-list">
              {reasons.map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
