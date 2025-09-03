export interface Pin {
  id: string;
  title: string;
  description: string;
  category: string;
  smell_category: string;
  smell_intensity: number;
  intensity: number;
  latitude: number;
  longitude: number;
  author: string;
  user_id: string;
  username?: string;
  avatar_url?: string;
  created_at: string;
  createdAt: string;
  images?: string[];
  media_urls?: string[];
  tags?: string[];
  weather?: {
    temperature: number;
    humidity: number;
    windSpeed: number;
  };
  likes: number;
  likes_count: number;
  comments: Comment[];
  comments_count: number;
  is_liked: boolean;
}

export interface Location {
  name: string;
  address: string;
  latitude: number;
  longitude: number;
  placeId?: string;
}

export interface Comment {
  id: string;
  author: string;
  content: string;
  createdAt: string;
}

export interface MapFilters {
  categories: string[];
  intensityRange: [number, number];
  timeRange: [Date | null, Date | null];
}

export interface WeatherInfo {
  temperature: number;
  humidity: number;
  windSpeed: number;
  description: string;
}

export interface UserLocation {
  latitude: number;
  longitude: number;
  accuracy?: number;
}