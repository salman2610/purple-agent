import React, { useState, useEffect } from "react";

// Simple DashboardLayout component without grid dependencies
const DashboardLayout = ({ 
  children, 
  layouts, 
  onLayoutChange, 
  onSaveLayout, 
  apiClient, 
  currentUser 
}) => {
  const [isEditing, setIsEditing] = useState(false);

  // Filter children that have widgetId prop
  const widgetChildren = React.Children.toArray(children).filter(
    child => child.props?.widgetId
  );

  return (
    <div style={{ width: "100%" }}>
      {/* Layout Controls */}
      <div style={{ 
        display: "flex", 
        justifyContent: "space-between", 
        alignItems: "center",
        marginBottom: "20px",
        padding: "15px",
        backgroundColor: "#222",
        border: "1px solid #444",
        borderRadius: "8px"
      }}>
        <h3 style={{ color: "#fff", margin: 0 }}>Dashboard Layout</h3>
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            onClick={() => setIsEditing(!isEditing)}
            style={{
              padding: "8px 16px",
              border: "none",
              borderRadius: "4px",
              backgroundColor: isEditing ? "#6c757d" : "#007bff",
              color: "white",
              cursor: "pointer",
              fontSize: "14px"
            }}
          >
            {isEditing ? "Stop Editing" : "Edit Layout"}
          </button>
          
          {isEditing && (
            <button
              onClick={() => onSaveLayout && onSaveLayout(layouts)}
              style={{
                padding: "8px 16px",
                border: "none",
                borderRadius: "4px",
                backgroundColor: "#28a745",
                color: "white",
                cursor: "pointer",
                fontSize: "14px"
              }}
            >
              Save Layout
            </button>
          )}
        </div>
      </div>

      {/* Dashboard Grid */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(400px, 1fr))",
        gap: "20px",
        width: "100%"
      }}>
        {widgetChildren.map((child, index) => (
          <div 
            key={child.props.widgetId || index}
            style={{
              border: isEditing ? "2px dashed #007bff" : "none",
              borderRadius: "8px",
              position: "relative"
            }}
          >
            {isEditing && (
              <div style={{
                position: "absolute",
                top: "5px",
                right: "5px",
                backgroundColor: "rgba(0, 123, 255, 0.8)",
                color: "white",
                padding: "2px 6px",
                borderRadius: "4px",
                fontSize: "10px",
                zIndex: 10
              }}>
                {child.props.widgetId}
              </div>
            )}
            {child}
          </div>
        ))}
      </div>

      {widgetChildren.length === 0 && (
        <div style={{
          textAlign: "center",
          padding: "40px",
          color: "#aaa",
          border: "2px dashed #444",
          borderRadius: "8px"
        }}>
          <p>No widgets available. Add some widgets to your dashboard.</p>
        </div>
      )}
    </div>
  );
};

export default DashboardLayout;
