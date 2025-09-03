import React from 'react';

interface FlowerIconProps {
  size?: number;
  className?: string;
  color?: string;
}

export const FlowerIcon: React.FC<FlowerIconProps> = ({ 
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
      {/* Flower petals */}
      <path
        d="M12 4C10 4 8.5 5.5 8.5 7.5C8.5 6 7 4.5 5 4.5C7 4.5 8.5 3 8.5 1C8.5 3 10 4.5 12 4.5Z"
        fill={color}
        opacity="0.7"
      />
      <path
        d="M12 4C14 4 15.5 5.5 15.5 7.5C15.5 6 17 4.5 19 4.5C17 4.5 15.5 3 15.5 1C15.5 3 14 4.5 12 4.5Z"
        fill={color}
        opacity="0.7"
      />
      <path
        d="M12 20C10 20 8.5 18.5 8.5 16.5C8.5 18 7 19.5 5 19.5C7 19.5 8.5 21 8.5 23C8.5 21 10 19.5 12 19.5Z"
        fill={color}
        opacity="0.7"
      />
      <path
        d="M12 20C14 20 15.5 18.5 15.5 16.5C15.5 18 17 19.5 19 19.5C17 19.5 15.5 21 15.5 23C15.5 21 14 19.5 12 19.5Z"
        fill={color}
        opacity="0.7"
      />
      <path
        d="M4 12C4 10 5.5 8.5 7.5 8.5C6 8.5 4.5 7 4.5 5C4.5 7 3 8.5 1 8.5C3 8.5 4.5 10 4.5 12Z"
        fill={color}
        opacity="0.7"
      />
      <path
        d="M20 12C20 10 18.5 8.5 16.5 8.5C18 8.5 19.5 7 19.5 5C19.5 7 21 8.5 23 8.5C21 8.5 19.5 10 19.5 12Z"
        fill={color}
        opacity="0.7"
      />
      <path
        d="M4 12C4 14 5.5 15.5 7.5 15.5C6 15.5 4.5 17 4.5 19C4.5 17 3 15.5 1 15.5C3 15.5 4.5 14 4.5 12Z"
        fill={color}
        opacity="0.7"
      />
      <path
        d="M20 12C20 14 18.5 15.5 16.5 15.5C18 15.5 19.5 17 19.5 19C19.5 17 21 15.5 23 15.5C21 15.5 19.5 14 19.5 12Z"
        fill={color}
        opacity="0.7"
      />
      
      {/* Flower center */}
      <circle
        cx="12"
        cy="12"
        r="3"
        fill={color}
      />
      
      {/* Center details */}
      <circle cx="11" cy="11" r="0.5" fill="#fff" opacity="0.8" />
      <circle cx="13" cy="11" r="0.5" fill="#fff" opacity="0.6" />
      <circle cx="12" cy="13" r="0.5" fill="#fff" opacity="0.7" />
    </svg>
  );
};

export default FlowerIcon;