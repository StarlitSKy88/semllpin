import React from 'react';

interface PomegranateIconProps {
  size?: number;
  className?: string;
  color?: string;
}

export const PomegranateIcon: React.FC<PomegranateIconProps> = ({ 
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
      {/* Pomegranate body */}
      <path
        d="M12 3C8.5 3 6 5.5 6 9C6 12.5 8.5 20 12 20C15.5 20 18 12.5 18 9C18 5.5 15.5 3 12 3Z"
        fill={color}
        opacity="0.8"
      />
      
      {/* Crown/top */}
      <path
        d="M10 3L10.5 1.5L11 3L11.5 1.5L12 3L12.5 1.5L13 3L13.5 1.5L14 3"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        fill="none"
      />
      
      {/* Seeds pattern */}
      <circle cx="10" cy="8" r="1" fill="#fff" opacity="0.6" />
      <circle cx="14" cy="8" r="1" fill="#fff" opacity="0.6" />
      <circle cx="12" cy="10" r="1" fill="#fff" opacity="0.6" />
      <circle cx="9" cy="12" r="1" fill="#fff" opacity="0.6" />
      <circle cx="15" cy="12" r="1" fill="#fff" opacity="0.6" />
      <circle cx="11" cy="14" r="1" fill="#fff" opacity="0.6" />
      <circle cx="13" cy="14" r="1" fill="#fff" opacity="0.6" />
      <circle cx="10" cy="16" r="1" fill="#fff" opacity="0.6" />
      <circle cx="14" cy="16" r="1" fill="#fff" opacity="0.6" />
      
      {/* Highlight */}
      <ellipse
        cx="10"
        cy="7"
        rx="2"
        ry="3"
        fill="#fff"
        opacity="0.2"
      />
    </svg>
  );
};

export default PomegranateIcon;