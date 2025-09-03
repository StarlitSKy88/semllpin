import React from 'react';

interface DecorativeBorderProps {
  width?: number;
  height?: number;
  className?: string;
  color?: string;
  position?: 'top' | 'bottom' | 'left' | 'right' | 'corner';
}

export const DecorativeBorder: React.FC<DecorativeBorderProps> = ({ 
  width = 200, 
  height = 20,
  className = '', 
  color = 'currentColor',
  position = 'top'
}) => {
  const getViewBox = () => {
    switch (position) {
      case 'corner':
        return '0 0 100 100';
      case 'left':
      case 'right':
        return `0 0 ${height} ${width}`;
      default:
        return `0 0 ${width} ${height}`;
    }
  };

  const renderPattern = () => {
    if (position === 'corner') {
      return (
        <g>
          {/* Corner ornament */}
          <path
            d="M10 10C20 10 30 20 30 30C30 20 40 10 50 10C40 10 30 5 30 0C30 5 20 10 10 10Z"
            fill={color}
            opacity="0.6"
          />
          <path
            d="M10 90C20 90 30 80 30 70C30 80 40 90 50 90C40 90 30 95 30 100C30 95 20 90 10 90Z"
            fill={color}
            opacity="0.6"
          />
          <path
            d="M90 10C90 20 80 30 70 30C80 30 90 40 90 50C90 40 95 30 100 30C95 30 90 20 90 10Z"
            fill={color}
            opacity="0.6"
          />
          <path
            d="M90 90C90 80 80 70 70 70C80 70 90 60 90 50C90 60 95 70 100 70C95 70 90 80 90 90Z"
            fill={color}
            opacity="0.6"
          />
          
          {/* Connecting curves */}
          <path
            d="M30 0C30 20 30 40 30 50C30 60 30 80 30 100"
            stroke={color}
            strokeWidth="2"
            strokeOpacity="0.4"
            fill="none"
          />
          <path
            d="M0 30C20 30 40 30 50 30C60 30 80 30 100 30"
            stroke={color}
            strokeWidth="2"
            strokeOpacity="0.4"
            fill="none"
          />
        </g>
      );
    }

    // Regular border pattern
    const patternCount = Math.floor(width / 40);
    const patterns = [];
    
    for (let i = 0; i < patternCount; i++) {
      const x = i * 40 + 20;
      patterns.push(
        <g key={i}>
          {/* Flower motif */}
          <circle
            cx={x}
            cy={height / 2}
            r="3"
            fill={color}
            opacity="0.7"
          />
          
          {/* Petals */}
          <path
            d={`M${x} ${height / 2 - 6}C${x - 3} ${height / 2 - 6} ${x - 6} ${height / 2 - 3} ${x - 6} ${height / 2}C${x - 6} ${height / 2 - 3} ${x - 3} ${height / 2} ${x} ${height / 2}Z`}
            fill={color}
            opacity="0.5"
          />
          <path
            d={`M${x} ${height / 2 + 6}C${x - 3} ${height / 2 + 6} ${x - 6} ${height / 2 + 3} ${x - 6} ${height / 2}C${x - 6} ${height / 2 + 3} ${x - 3} ${height / 2} ${x} ${height / 2}Z`}
            fill={color}
            opacity="0.5"
          />
          <path
            d={`M${x + 6} ${height / 2}C${x + 6} ${height / 2 - 3} ${x + 3} ${height / 2 - 6} ${x} ${height / 2 - 6}C${x + 3} ${height / 2 - 6} ${x} ${height / 2 - 3} ${x} ${height / 2}Z`}
            fill={color}
            opacity="0.5"
          />
          <path
            d={`M${x + 6} ${height / 2}C${x + 6} ${height / 2 + 3} ${x + 3} ${height / 2 + 6} ${x} ${height / 2 + 6}C${x + 3} ${height / 2 + 6} ${x} ${height / 2 + 3} ${x} ${height / 2}Z`}
            fill={color}
            opacity="0.5"
          />
          
          {/* Connecting vine */}
          {i < patternCount - 1 && (
            <path
              d={`M${x + 6} ${height / 2}Q${x + 20} ${height / 2 - 4} ${x + 34} ${height / 2}`}
              stroke={color}
              strokeWidth="1"
              strokeOpacity="0.4"
              fill="none"
            />
          )}
        </g>
      );
    }
    
    return patterns;
  };

  return (
    <svg
      width={position === 'corner' ? 100 : (position === 'left' || position === 'right' ? height : width)}
      height={position === 'corner' ? 100 : (position === 'left' || position === 'right' ? width : height)}
      viewBox={getViewBox()}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {renderPattern()}
    </svg>
  );
};

export default DecorativeBorder;