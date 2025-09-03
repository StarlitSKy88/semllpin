import React from 'react';

interface LeafIconProps {
  size?: number;
  className?: string;
  color?: string;
}

export const LeafIcon: React.FC<LeafIconProps> = ({ 
  size = 24, 
  className = '', 
  color = 'currentColor' 
}) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {/* Main leaf shape */}
      <path
        d="M3 20C3 20 8 15 12 10C16 5 21 2 21 2C21 2 18 7 16 12C14 17 9 20 3 20Z"
        fill={color}
        opacity="0.8"
      />
      
      {/* Leaf veins */}
      <path
        d="M3 20C5 18 7 16 9 14C11 12 13 10 15 8C17 6 19 4 21 2"
        stroke="#fff"
        strokeWidth="1"
        strokeOpacity="0.4"
        fill="none"
      />
      
      {/* Secondary veins */}
      <path
        d="M6 18C8 16 10 14 12 12"
        stroke="#fff"
        strokeWidth="0.8"
        strokeOpacity="0.3"
        fill="none"
      />
      <path
        d="M9 16C11 14 13 12 15 10"
        stroke="#fff"
        strokeWidth="0.8"
        strokeOpacity="0.3"
        fill="none"
      />
      <path
        d="M12 14C14 12 16 10 18 8"
        stroke="#fff"
        strokeWidth="0.8"
        strokeOpacity="0.3"
        fill="none"
      />
      
      {/* Leaf stem */}
      <path
        d="M3 20L1 22"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
      />
      
      {/* Highlight */}
      <ellipse
        cx="8"
        cy="15"
        rx="2"
        ry="3"
        fill="#fff"
        opacity="0.2"
        transform="rotate(-45 8 15)"
      />
    </svg>
  );
};

export default LeafIcon;