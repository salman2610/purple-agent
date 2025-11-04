import React, { useState } from 'react';

const FilterPanel = ({ onFilterChange, filters, loading = false }) => {
  const [localFilters, setLocalFilters] = useState(filters || {});

  const handleFilterChange = (key, value) => {
    const newFilters = { ...localFilters, [key]: value };
    setLocalFilters(newFilters);
    onFilterChange(newFilters);
  };

  const clearFilters = () => {
    const clearedFilters = {};
    setLocalFilters(clearedFilters);
    onFilterChange(clearedFilters);
  };

  return (
    <div style={{
      backgroundColor: '#222',
      border: '1px solid #444',
      borderRadius: '8px',
      padding: '15px',
      marginBottom: '20px'
    }}>
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        marginBottom: '15px'
      }}>
        <h4 style={{ color: '#fff', margin: 0 }}>🔍 Filters</h4>
        <button 
          onClick={clearFilters}
          style={{
            padding: '5px 10px',
            backgroundColor: '#6c757d',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '12px'
          }}
        >
          Clear All
        </button>
      </div>

      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
        gap: '10px' 
      }}>
        {/* Date Range */}
        <div>
          <label style={{ color: '#aaa', fontSize: '12px', display: 'block', marginBottom: '5px' }}>
            Start Date
          </label>
          <input
            type="datetime-local"
            value={localFilters.startDate || ''}
            onChange={(e) => handleFilterChange('startDate', e.target.value)}
            style={{
              width: '100%',
              padding: '8px',
              backgroundColor: '#333',
              color: '#fff',
              border: '1px solid #444',
              borderRadius: '4px',
              fontSize: '12px'
            }}
          />
        </div>

        <div>
          <label style={{ color: '#aaa', fontSize: '12px', display: 'block', marginBottom: '5px' }}>
            End Date
          </label>
          <input
            type="datetime-local"
            value={localFilters.endDate || ''}
            onChange={(e) => handleFilterChange('endDate', e.target.value)}
            style={{
              width: '100%',
              padding: '8px',
              backgroundColor: '#333',
              color: '#fff',
              border: '1px solid #444',
              borderRadius: '4px',
              fontSize: '12px'
            }}
          />
        </div>

        {/* Hostname Filter */}
        <div>
          <label style={{ color: '#aaa', fontSize: '12px', display: 'block', marginBottom: '5px' }}>
            Hostname
          </label>
          <input
            type="text"
            placeholder="Filter by hostname..."
            value={localFilters.hostname || ''}
            onChange={(e) => handleFilterChange('hostname', e.target.value)}
            style={{
              width: '100%',
              padding: '8px',
              backgroundColor: '#333',
              color: '#fff',
              border: '1px solid #444',
              borderRadius: '4px',
              fontSize: '12px'
            }}
          />
        </div>

        {/* CPU Range */}
        <div>
          <label style={{ color: '#aaa', fontSize: '12px', display: 'block', marginBottom: '5px' }}>
            CPU Usage (%)
          </label>
          <div style={{ display: 'flex', gap: '5px' }}>
            <input
              type="number"
              placeholder="Min"
              min="0"
              max="100"
              value={localFilters.minCpu || ''}
              onChange={(e) => handleFilterChange('minCpu', e.target.value)}
              style={{
                flex: 1,
                padding: '8px',
                backgroundColor: '#333',
                color: '#fff',
                border: '1px solid #444',
                borderRadius: '4px',
                fontSize: '12px'
              }}
            />
            <input
              type="number"
              placeholder="Max"
              min="0"
              max="100"
              value={localFilters.maxCpu || ''}
              onChange={(e) => handleFilterChange('maxCpu', e.target.value)}
              style={{
                flex: 1,
                padding: '8px',
                backgroundColor: '#333',
                color: '#fff',
                border: '1px solid #444',
                borderRadius: '4px',
                fontSize: '12px'
              }}
            />
          </div>
        </div>

        {/* Memory Range */}
        <div>
          <label style={{ color: '#aaa', fontSize: '12px', display: 'block', marginBottom: '5px' }}>
            Memory Usage (%)
          </label>
          <div style={{ display: 'flex', gap: '5px' }}>
            <input
              type="number"
              placeholder="Min"
              min="0"
              max="100"
              value={localFilters.minMemory || ''}
              onChange={(e) => handleFilterChange('minMemory', e.target.value)}
              style={{
                flex: 1,
                padding: '8px',
                backgroundColor: '#333',
                color: '#fff',
                border: '1px solid #444',
                borderRadius: '4px',
                fontSize: '12px'
              }}
            />
            <input
              type="number"
              placeholder="Max"
              min="0"
              max="100"
              value={localFilters.maxMemory || ''}
              onChange={(e) => handleFilterChange('maxMemory', e.target.value)}
              style={{
                flex: 1,
                padding: '8px',
                backgroundColor: '#333',
                color: '#fff',
                border: '1px solid #444',
                borderRadius: '4px',
                fontSize: '12px'
              }}
            />
          </div>
        </div>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', marginTop: '10px', color: '#007bff' }}>
          Applying filters...
        </div>
      )}
    </div>
  );
};

export default FilterPanel;
