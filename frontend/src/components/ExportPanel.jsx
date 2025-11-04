import React from 'react';
import ExportButton from './ExportButton';

const ExportPanel = ({ filters, apiClient }) => {
  return (
    <div style={{
      backgroundColor: '#222',
      border: '1px solid #444',
      borderRadius: '8px',
      padding: '15px',
      marginBottom: '20px'
    }}>
      <h4 style={{ color: '#fff', margin: '0 0 15px 0' }}>📁 Export Data</h4>
      
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '10px'
      }}>
        <div style={{ textAlign: 'center' }}>
          <p style={{ color: '#aaa', fontSize: '12px', margin: '0 0 8px 0' }}>
            Agent Data
          </p>
          <ExportButton
            exportType="agent-data"
            filters={filters}
            apiClient={apiClient}
            buttonText="Export CSV"
            variant="primary"
          />
        </div>

        <div style={{ textAlign: 'center' }}>
          <p style={{ color: '#aaa', fontSize: '12px', margin: '0 0 8px 0' }}>
            Incidents
          </p>
          <ExportButton
            exportType="incidents"
            filters={filters}
            apiClient={apiClient}
            buttonText="Export CSV"
            variant="warning"
          />
        </div>

        <div style={{ textAlign: 'center' }}>
          <p style={{ color: '#aaa', fontSize: '12px', margin: '0 0 8px 0' }}>
            Full Report
          </p>
          <ExportButton
            exportType="dashboard-report"
            filters={filters}
            apiClient={apiClient}
            buttonText="Export Report"
            variant="success"
          />
        </div>
      </div>

      <div style={{ 
        marginTop: '10px', 
        fontSize: '11px', 
        color: '#666',
        textAlign: 'center'
      }}>
        Exports will use current filter settings
      </div>
    </div>
  );
};

export default ExportPanel;
