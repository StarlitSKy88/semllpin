import React from 'react';

interface PetalIconProps {
  size?: number;
  className?: string;
  color?: string;
}

export const PetalIcon: React.FC<PetalIconProps> = ({ 
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
      {/* Petal shape */}
      <path
        d="M12 2C8 2 5 5 5 9C5 13 8 16 12 20C16 16 19 13 19 9C19 5 16 2 12 2Z"
        fill={color}
        opacity="0.8"
      />
      
      {/* Petal center line */}
      <path
        d="M12 2C12 6 12 10 12 14C12 16 12 18 12 20"
        stroke="#fff"
        strokeWidth="1.5"
        strokeOpacity="0.4"
        fill="none"
      />
      
      {/* Side curves */}
      <path
        d="M8 8C10 10 12 12 12 14"
        stroke="#fff"
        strokeWidth="1"
        strokeOpacity="0.3"
        fill="none"
      />
      <path
        d="M16 8C14 10 12 12 12 14"
        stroke="#fff"
        strokeWidth="1"
        strokeOpacity="0.3"
        fill="none"
      />
      
      {/* Highlight gradient effect */}
      <ellipse
        cx="10"
        cy="8"
        rx="2"
        ry="4"
        fill="#fff"
        opacity="0.2"
      />
      
      {/* Subtle texture dots */}
      <circle cx="9" cy="6" r="0.5" fill="#fff" opacity="0.3" />
      <circle cx="15" cy="6" r="0.5" fill="#fff" opacity="0.3" />
      <circle cx="8" cy="10" r="0.5" fill="#fff" opacity="0.2" />
      <circle cx="16" cy="10" r="0.5" fill="#fff" opacity="0.2" />
    </svg>
  );
};

export default PetalIcon;