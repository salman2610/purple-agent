import React from 'react';
import { PieChart, Pie, Cell, Legend, Tooltip, ResponsiveContainer } from 'recharts';

function MetricsChart({ cpu, memory, disk, onMetricClick }) {
  const data = [
    { name: 'CPU', value: cpu, color: '#8884d8' },
    { name: 'Memory', value: memory, color: '#82ca9d' },
    { name: 'Disk', value: disk, color: '#ffc658' }
  ];
  
  const handlePieClick = (data, index) => {
    if (onMetricClick && data && data.name) {
      onMetricClick({
        metric: `${data.name.toLowerCase()}_usage`,
        value: data.value,
        range: getValueRange(data.value)
      });
    }
  };

  const getValueRange = (value) => {
    if (value >= 90) return '90-100';
    if (value >= 80) return '80-90';
    if (value >= 70) return '70-80';
    if (value >= 50) return '50-70';
    return '0-50';
  };

  return (
    <div style={darkStyles.gridCard}>
      <h3 style={{ color: '#fff', marginBottom: "15px" }}>System Metrics</h3>
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={100}
            label={({ name, value }) => `${name}: ${value?.toFixed(1)}%`}
            onClick={handlePieClick}
            style={{ cursor: 'pointer' }}
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip 
            formatter={(value) => [`${value?.toFixed(1)}%`, 'Usage']}
            contentStyle={{ backgroundColor: '#222', border: '1px solid #444' }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
      <div style={{ marginTop: "10px", display: "flex", justifyContent: "space-around" }}>
        {data.map((item, index) => (
          <span 
            key={index} 
            style={{ color: item.color, cursor: 'pointer' }}
            onClick={() => handlePieClick(item)}
          >
            {item.name}: {item.value?.toFixed(1)}%
          </span>
        ))}
      </div>
    </div>
  );
}

const darkStyles = {
  gridCard: {
    backgroundColor: "#222",
    border: "1px solid #444",
    padding: "20px",
    borderRadius: "8px",
    width: "100%",
    textAlign: "center",
    boxSizing: "border-box",
    height: "100%"
  }
};

export default MetricsChart;
