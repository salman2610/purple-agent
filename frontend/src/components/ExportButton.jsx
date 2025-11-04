import React, { useState } from 'react';

const ExportButton = ({ 
  exportType, 
  filters = {}, 
  apiClient, 
  buttonText = "Export",
  variant = "primary"
}) => {
  const [exporting, setExporting] = useState(false);

  const handleExport = async () => {
    setExporting(true);
    try {
      // Build query params from filters
      const params = new URLSearchParams();
      
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          params.append(key, value);
        }
      });

      // Determine endpoint based on export type
      let endpoint = '';
      switch (exportType) {
        case 'agent-data':
          endpoint = '/export/agent-data/csv';
          break;
        case 'incidents':
          endpoint = '/export/incidents/csv';
          break;
        case 'dashboard-report':
          endpoint = '/export/dashboard-report';
          break;
        default:
          throw new Error('Unknown export type');
      }

      // Make API call
      const response = await apiClient.get(`${endpoint}?${params}`, {
        responseType: 'blob' // Important for file download
      });

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      // Extract filename from response headers or generate one
      const contentDisposition = response.headers['content-disposition'];
      let filename = `export_${new Date().getTime()}.csv`;
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }
      
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

    } catch (error) {
      console.error('Export error:', error);
      alert('Export failed. Please try again.');
    } finally {
      setExporting(false);
    }
  };

  const getButtonStyle = () => {
    const baseStyle = {
      padding: '8px 16px',
      border: 'none',
      borderRadius: '4px',
      cursor: exporting ? 'not-allowed' : 'pointer',
      fontSize: '14px',
      fontWeight: '500',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      opacity: exporting ? 0.7 : 1
    };

    switch (variant) {
      case 'success':
        return { ...baseStyle, backgroundColor: '#28a745', color: 'white' };
      case 'warning':
        return { ...baseStyle, backgroundColor: '#ffc107', color: 'black' };
      case 'primary':
      default:
        return { ...baseStyle, backgroundColor: '#007bff', color: 'white' };
    }
  };

  return (
    <button 
      onClick={handleExport}
      disabled={exporting}
      style={getButtonStyle()}
    >
      {exporting ? '⏳' : '📊'} 
      {exporting ? 'Exporting...' : buttonText}
    </button>
  );
};

export default ExportButton;
