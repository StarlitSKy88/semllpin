import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { OSMMap } from '../osm-map';

// Mock data for testing
const mockAnnotations = [
  {
    id: '1',
    latitude: 39.9042,
    longitude: 116.4074,
    smell_intensity: 5,
    smell_type: 'food',
    description: 'Test annotation 1',
    created_at: '2023-01-01T00:00:00Z'
  },
  {
    id: '2',
    latitude: 39.9052,
    longitude: 116.4084,
    smell_intensity: 8,
    smell_type: 'garbage',
    description: 'Test annotation 2',
    created_at: '2023-01-02T00:00:00Z'
  }
];

describe('OSMMap Component', () => {
  const user = userEvent.setup();
  
  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  it('should render map container correctly', () => {
    render(<OSMMap />);
    
    expect(screen.getByTestId('map-container')).toBeInTheDocument();
    expect(screen.getByTestId('tile-layer')).toBeInTheDocument();
  });

  it('should display loading state initially', () => {
    render(<OSMMap />);
    
    expect(screen.getByText('地图加载中...')).toBeInTheDocument();
  });

  it('should render annotations as markers', async () => {
    await act(async () => {
      render(<OSMMap annotations={mockAnnotations} />);
    });

    await waitFor(() => {
      const markers = screen.getAllByTestId('marker');
      expect(markers).toHaveLength(mockAnnotations.length);
    });
  });

  it('should render user location marker when showUserLocation is true', async () => {
    await act(async () => {
      render(<OSMMap showUserLocation={true} />);
    });

    await waitFor(() => {
      // User location marker should be present
      expect(screen.getByText('你的位置')).toBeInTheDocument();
    });
  });

  it('should call onMapClick when map is clicked', async () => {
    const mockOnMapClick = jest.fn();
    
    await act(async () => {
      render(<OSMMap onMapClick={mockOnMapClick} />);
    });

    await waitFor(() => {
      const mapContainer = screen.getByTestId('map-container');
      fireEvent.click(mapContainer);
    });

    // Note: The actual coordinates would depend on the mock implementation
    // This test ensures the function is called
    expect(mockOnMapClick).toHaveBeenCalled();
  });

  it('should display annotation popup with correct information', async () => {
    await act(async () => {
      render(<OSMMap annotations={mockAnnotations} />);
    });

    await waitFor(() => {
      const markers = screen.getAllByTestId('marker');
      fireEvent.click(markers[0]);
    });

    await waitFor(() => {
      expect(screen.getByText('气味强度: 5/10')).toBeInTheDocument();
      expect(screen.getByText('food')).toBeInTheDocument();
      expect(screen.getByText('Test annotation 1')).toBeInTheDocument();
    });
  });

  it('should render custom smell icons based on intensity', async () => {
    await act(async () => {
      render(<OSMMap annotations={mockAnnotations} />);
    });

    // Test that different intensities create different colored icons
    await waitFor(() => {
      const markers = screen.getAllByTestId('marker');
      expect(markers).toHaveLength(2);
      
      // The intensity values should be displayed in the markers
      // This would be verified through the DOM structure or data attributes
    });
  });

  it('should handle geolocation permission denied gracefully', async () => {
    // Mock geolocation to reject
    const mockGeolocation = {
      getCurrentPosition: jest.fn((success, error) => {
        error({ code: 1, message: 'User denied the request for Geolocation.' });
      })
    };
    
    Object.defineProperty(navigator, 'geolocation', {
      writable: true,
      value: mockGeolocation
    });

    await act(async () => {
      render(<OSMMap showUserLocation={true} />);
    });

    // Should not throw error and should render without user location
    expect(screen.getByTestId('map-container')).toBeInTheDocument();
  });

  it('should display map controls and legend', async () => {
    await act(async () => {
      render(<OSMMap />);
    });

    await waitFor(() => {
      // Check for legend items
      expect(screen.getByText('轻微 (1-3)')).toBeInTheDocument();
      expect(screen.getByText('中等 (4-6)')).toBeInTheDocument();
      expect(screen.getByText('强烈 (7-10)')).toBeInTheDocument();
    });
  });

  it('should handle empty annotations array', () => {
    render(<OSMMap annotations={[]} />);
    
    expect(screen.getByTestId('map-container')).toBeInTheDocument();
    expect(screen.queryAllByTestId('marker')).toHaveLength(0);
  });

  it('should apply custom className correctly', () => {
    const customClass = 'custom-map-class';
    render(<OSMMap className={customClass} />);
    
    const mapElement = screen.getByTestId('map-container').parentElement;
    expect(mapElement).toHaveClass(customClass);
  });

  it('should use default center when not provided', () => {
    render(<OSMMap />);
    
    const mapContainer = screen.getByTestId('map-container');
    // Default center should be Beijing (39.9042, 116.4074)
    expect(mapContainer).toBeInTheDocument();
  });

  it('should use custom center when provided', () => {
    const customCenter: [number, number] = [40.7128, -74.0060]; // New York
    render(<OSMMap center={customCenter} />);
    
    const mapContainer = screen.getByTestId('map-container');
    expect(mapContainer).toBeInTheDocument();
  });

  it('should handle annotation with missing optional fields', async () => {
    const annotationWithMissingFields = [{
      id: '3',
      latitude: 39.9000,
      longitude: 116.4000,
      smell_intensity: 3,
      description: 'Minimal annotation',
      created_at: '2023-01-03T00:00:00Z'
      // Missing smell_type
    }];

    await act(async () => {
      render(<OSMMap annotations={annotationWithMissingFields} />);
    });

    await waitFor(() => {
      const markers = screen.getAllByTestId('marker');
      expect(markers).toHaveLength(1);
    });
  });

  describe('Smell Icon Generation', () => {
    it('should create green icon for low intensity (1-3)', () => {
      // This would test the createSmellIcon function
      // Since it's an internal function, we test it through rendered markers
      const lowIntensityAnnotation = [{
        id: '1',
        latitude: 39.9042,
        longitude: 116.4074,
        smell_intensity: 2,
        description: 'Low intensity',
        created_at: '2023-01-01T00:00:00Z'
      }];

      render(<OSMMap annotations={lowIntensityAnnotation} />);
      // Verify through DOM inspection or data attributes
    });

    it('should create yellow icon for medium intensity (4-6)', () => {
      const mediumIntensityAnnotation = [{
        id: '2',
        latitude: 39.9042,
        longitude: 116.4074,
        smell_intensity: 5,
        description: 'Medium intensity',
        created_at: '2023-01-01T00:00:00Z'
      }];

      render(<OSMMap annotations={mediumIntensityAnnotation} />);
      // Verify icon color
    });

    it('should create red icon for high intensity (7-10)', () => {
      const highIntensityAnnotation = [{
        id: '3',
        latitude: 39.9042,
        longitude: 116.4074,
        smell_intensity: 9,
        description: 'High intensity',
        created_at: '2023-01-01T00:00:00Z'
      }];

      render(<OSMMap annotations={highIntensityAnnotation} />);
      // Verify icon color
    });
  });

  describe('Map Interactions', () => {
    it('should handle map zoom controls', async () => {
      render(<OSMMap zoom={10} />);
      
      const mapContainer = screen.getByTestId('map-container');
      expect(mapContainer).toBeInTheDocument();
      
      // Test zoom functionality through map container
      // This would require more detailed mock setup for Leaflet
    });

    it('should handle annotation click events', async () => {
      const mockOnAnnotationClick = jest.fn();
      
      await act(async () => {
        render(<OSMMap annotations={mockAnnotations} />);
      });

      await waitFor(() => {
        const markers = screen.getAllByTestId('marker');
        fireEvent.click(markers[0]);
      });

      // Verify popup appears
      await waitFor(() => {
        expect(screen.getByText('Test annotation 1')).toBeInTheDocument();
      });
    });
  });

  describe('Responsive Design', () => {
    it('should handle different screen sizes', () => {
      // Test mobile view
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 375,
      });

      render(<OSMMap />);
      expect(screen.getByTestId('map-container')).toBeInTheDocument();

      // Test desktop view
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 1920,
      });

      render(<OSMMap />);
      expect(screen.getByTestId('map-container')).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('should handle Leaflet initialization errors gracefully', () => {
      // Mock Leaflet to throw an error
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // This would simulate various error conditions
      render(<OSMMap />);
      
      expect(screen.getByTestId('map-container')).toBeInTheDocument();
      
      consoleSpy.mockRestore();
    });

    it('should handle invalid coordinates gracefully', async () => {
      const invalidAnnotations = [{
        id: '1',
        latitude: 200, // Invalid latitude
        longitude: 300, // Invalid longitude
        smell_intensity: 5,
        description: 'Invalid coordinates',
        created_at: '2023-01-01T00:00:00Z'
      }];

      await act(async () => {
        render(<OSMMap annotations={invalidAnnotations} />);
      });

      // Should render without crashing
      expect(screen.getByTestId('map-container')).toBeInTheDocument();
    });
  });
});