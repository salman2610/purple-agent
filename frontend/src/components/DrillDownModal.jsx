import React from 'react';

const DrillDownModal = ({ isOpen, onClose, metricData, apiClient }) => {
  const [details, setDetails] = React.useState([]);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    if (isOpen && metricData) {
      fetchMetricDetails();
    }
  }, [isOpen, metricData]);

  const fetchMetricDetails = async () => {
    if (!metricData) return;
    
    setLoading(true);
    try {
      const response = await apiClient.get('/agent/data/metric-details', {
        params: {
          metric: metricData.metric,
          value_range: metricData.range,
          hostname: metricData.hostname
        }
      });
      setDetails(response.data.data || []);
    } catch (error) {
      console.error('Error fetching metric details:', error);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    }}>
      <div style={{
        backgroundColor: '#222',
        border: '1px solid #444',
        borderRadius: '8px',
        padding: '20px',
        maxWidth: '90%',
        maxHeight: '80%',
        overflow: 'auto',
        width: '600px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ color: '#fff', margin: 0 }}>
            🔍 {metricData?.metric?.replace('_', ' ').toUpperCase()} Details
          </h3>
          <button 
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: '#fff',
              fontSize: '20px',
              cursor: 'pointer'
            }}
          >
            ✕
          </button>
        </div>

        {metricData && (
          <div style={{ marginBottom: '15px', color: '#aaa' }}>
            <p>Showing data for {metricData.metric} in range {metricData.range}%</p>
            <p>Current value: <strong style={{ color: '#fff' }}>{metricData.value?.toFixed(1)}%</strong></p>
          </div>
        )}

        {loading ? (
          <div style={{ textAlign: 'center', color: '#007bff' }}>
            Loading details...
          </div>
        ) : (
          <div style={{ maxHeight: '400px', overflow: 'auto' }}>
            {details.length > 0 ? (
              <table style={{ width: '100%', borderCollapse: 'collapse', color: '#fff' }}>
                <thead>
                  <tr style={{ backgroundColor: '#333' }}>
                    <th style={{ padding: '10px', border: '1px solid #444', textAlign: 'left' }}>Timestamp</th>
                    <th style={{ padding: '10px', border: '1px solid #444', textAlign: 'left' }}>Hostname</th>
                    <th style={{ padding: '10px', border: '1px solid #444', textAlign: 'left' }}>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {details.map((item, index) => (
                    <tr key={index} style={{ backgroundColor: index % 2 === 0 ? '#222' : '#2a2a2a' }}>
                      <td style={{ padding: '10px', border: '1px solid #444', fontSize: '12px' }}>
                        {new Date(item.timestamp).toLocaleString()}
                      </td>
                      <td style={{ padding: '10px', border: '1px solid #444', fontSize: '12px' }}>
                        {item.hostname || 'N/A'}
                      </td>
                      <td style={{ padding: '10px', border: '1px solid #444', fontSize: '12px' }}>
                        <strong>{item.metric_value?.toFixed(1)}%</strong>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div style={{ textAlign: 'center', color: '#aaa', padding: '20px' }}>
                No detailed data found for this metric range.
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop: '20px', textAlign: 'right' }}>
          <button 
            onClick={onClose}
            style={{
              padding: '8px 16px',
              backgroundColor: '#6c757d',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default DrillDownModal;
