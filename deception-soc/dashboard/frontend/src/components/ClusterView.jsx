import React from 'react';

export default function ClusterView({ clusterData }) {
  if (!clusterData || clusterData.status === 'not_trained') {
    return (
      <div className="ai-section">
        <div className="ai-section-title">🔬 Cluster Classification</div>
        <div style={{ color: '#555', fontSize: '13px' }}>AI model not yet trained. Collect more sessions first.</div>
      </div>
    );
  }
  return (
    <div className="ai-section">
      <div className="ai-section-title">🔬 Cluster Classification</div>
      <div style={{ fontSize: '16px', fontWeight: '700', color: 'var(--purple)', marginBottom: '8px' }}>
        {clusterData.cluster_label || 'Unknown'}
      </div>
      <div style={{ fontSize: '12px', color: '#888', marginBottom: '8px' }}>
        {clusterData.cluster_description || ''}
      </div>
      <div style={{ fontSize: '12px', color: '#888' }}>
        Confidence: {((clusterData.confidence || 0) * 100).toFixed(1)}%
      </div>
      <div className="confidence-bar" style={{ marginTop: '8px' }}>
        <div className="confidence-fill" style={{ width: `${(clusterData.confidence || 0) * 100}%` }} />
      </div>
    </div>
  );
}
