// Import the components for the collection
import { PomegranateIcon as PomegranateIconComponent } from './PomegranateIcon';
import { FlowerIcon as FlowerIconComponent } from './FlowerIcon';
import { LeafIcon as LeafIconComponent } from './LeafIcon';
import { PetalIcon as PetalIconComponent } from './PetalIcon';
import { OrientalPattern as OrientalPatternComponent } from './OrientalPattern';
import { DecorativeBorder as DecorativeBorderComponent } from './DecorativeBorder';

// Named exports for individual components
export const PomegranateIcon = PomegranateIconComponent;
export const FlowerIcon = FlowerIconComponent;
export const LeafIcon = LeafIconComponent;
export const PetalIcon = PetalIconComponent;
export const OrientalPattern = OrientalPatternComponent;
export const DecorativeBorder = DecorativeBorderComponent;

// Icon collection for easy access
export const PomegranateIcons = {
  Pomegranate: PomegranateIconComponent,
  Flower: FlowerIconComponent,
  Leaf: LeafIconComponent,
  Petal: PetalIconComponent,
  OrientalPattern: OrientalPatternComponent,
  DecorativeBorder: DecorativeBorderComponent,
};

// Type definitions
export interface IconProps {
  size?: number;
  className?: string;
  color?: string;
}

export interface DecorativeBorderProps extends IconProps {
  width?: number;
  height?: number;
  position?: 'top' | 'bottom' | 'left' | 'right' | 'corner';
}

export interface OrientalPatternProps extends IconProps {
  // OrientalPattern specific props can be added here
}

// Utility function to get icon by name
export const getIcon = (name: keyof typeof PomegranateIcons) => {
  return PomegranateIcons[name];
};

// Default export
export default PomegranateIcons;