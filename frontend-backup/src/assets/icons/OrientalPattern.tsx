import React from 'react';

interface OrientalPatternProps {
  size?: number;
  className?: string;
  color?: string;
}

export const OrientalPattern: React.FC<OrientalPatternProps> = ({ 
  size = 48, 
  className = '', 
  color = 'currentColor' 
}) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {/* Central flower motif */}
      <circle
        cx="24"
        cy="24"
        r="6"
        fill={color}
        opacity="0.8"
      />
      
      {/* Surrounding petals */}
      <path
        d="M24 12C22 12 20 14 20 16C20 14 18 12 16 12C18 12 20 10 20 8C20 10 22 12 24 12Z"
        fill={color}
        opacity="0.6"
      />
      <path
        d="M24 36C22 36 20 34 20 32C20 34 18 36 16 36C18 36 20 38 20 40C20 38 22 36 24 36Z"
        fill={color}
        opacity="0.6"
      />
      <path
        d="M36 24C36 22 34 20 32 20C34 20 36 18 36 16C36 18 38 20 40 20C38 20 36 22 36 24Z"
        fill={color}
        opacity="0.6"
      />
      <path
        d="M12 24C12 22 14 20 16 20C14 20 12 18 12 16C12 18 10 20 8 20C10 20 12 22 12 24Z"
        fill={color}
        opacity="0.6"
      />
      
      {/* Diagonal petals */}
      <path
        d="M32 16C30 16 28 18 28 20C28 18 26 16 24 16C26 16 28 14 28 12C28 14 30 16 32 16Z"
        fill={color}
        opacity="0.5"
      />
      <path
        d="M16 32C18 32 20 30 20 28C20 30 22 32 24 32C22 32 20 34 20 36C20 34 18 32 16 32Z"
        fill={color}
        opacity="0.5"
      />
      <path
        d="M32 32C30 32 28 30 28 28C28 30 26 32 24 32C26 32 28 34 28 36C28 34 30 32 32 32Z"
        fill={color}
        opacity="0.5"
      />
      <path
        d="M16 16C18 16 20 18 20 20C20 18 22 16 24 16C22 16 20 14 20 12C20 14 18 16 16 16Z"
        fill={color}
        opacity="0.5"
      />
      
      {/* Corner decorations */}
      <circle cx="8" cy="8" r="2" fill={color} opacity="0.4" />
      <circle cx="40" cy="8" r="2" fill={color} opacity="0.4" />
      <circle cx="8" cy="40" r="2" fill={color} opacity="0.4" />
      <circle cx="40" cy="40" r="2" fill={color} opacity="0.4" />
      
      {/* Connecting lines */}
      <path
        d="M8 8L16 16"
        stroke={color}
        strokeWidth="1"
        strokeOpacity="0.3"
      />
      <path
        d="M40 8L32 16"
        stroke={color}
        strokeWidth="1"
        strokeOpacity="0.3"
      />
      <path
        d="M8 40L16 32"
        stroke={color}
        strokeWidth="1"
        strokeOpacity="0.3"
      />
      <path
        d="M40 40L32 32"
        stroke={color}
        strokeWidth="1"
        strokeOpacity="0.3"
      />
      
      {/* Central highlight */}
      <circle
        cx="24"
        cy="24"
        r="3"
        fill="#fff"
        opacity="0.3"
      />
    </svg>
  );
};

export default OrientalPattern;