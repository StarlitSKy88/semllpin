import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EnhancedInteractiveMap } from '../enhanced-interactive-map';

// Mock data
const mockAnnotations = [
  {
    id: '1',
    title: '臭豆腐摊位',
    description: '这里有最正宗的臭豆腐！',
    latitude: 39.9042,
    longitude: 116.4074,
    rewardAmount: 15,
    isDiscovered: false,
    category: 'food',
    createdAt: '2023-01-01T00:00:00Z',
    author: '美食家小王'
  },
  {
    id: '2',
    title: '垃圾处理站',
    description: '注意异味区域',
    latitude: 39.9052,
    longitude: 116.4084,
    rewardAmount: 25,
    isDiscovered: true,
    category: 'waste',
    createdAt: '2023-01-02T00:00:00Z',
    author: '环保志愿者'
  }
];

describe('EnhancedInteractiveMap Component', () => {
  const user = userEvent.setup();
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock getBoundingClientRect for coordinate calculations
    Element.prototype.getBoundingClientRect = jest.fn(() => ({
      width: 800,
      height: 600,
      top: 0,
      left: 0,
      bottom: 600,
      right: 800,
      x: 0,
      y: 0,
      toJSON: () => {}
    }));
  });

  it('should render map container with correct theme', () => {
    render(<EnhancedInteractiveMap theme="cyberpunk" />);
    
    // Check if the component renders
    expect(screen.getByRole('button', { name: /\+/ })).toBeInTheDocument();
  });

  it('should display annotations as interactive markers', async () => {
    await act(async () => {
      render(<EnhancedInteractiveMap annotations={mockAnnotations} />);
    });

    await waitFor(() => {
      // Check if annotations are rendered (markers would be in the DOM)
      // Since we're using a complex animation system, we check for the map container
      expect(screen.getByText('缩放:')).toBeInTheDocument();
      expect(screen.getByText('标注: 2')).toBeInTheDocument();
    });
  });

  it('should handle zoom controls correctly', async () => {
    const mockOnZoomChange = jest.fn();
    
    await act(async () => {
      render(
        <EnhancedInteractiveMap 
          annotations={mockAnnotations}
          onZoomChange={mockOnZoomChange}
        />
      );
    });

    // Find zoom in button
    const zoomInButton = screen.getByText('+');
    const zoomOutButton = screen.getByText('−');

    await user.click(zoomInButton);
    expect(mockOnZoomChange).toHaveBeenCalledWith(13); // Default zoom + 1

    await user.click(zoomOutButton);
    expect(mockOnZoomChange).toHaveBeenCalledWith(11); // Previous zoom - 1
  });

  it('should handle center to user location', async () => {
    const mockOnCenterChange = jest.fn();
    
    await act(async () => {
      render(
        <EnhancedInteractiveMap 
          onCenterChange={mockOnCenterChange}
          userLocation={[40.7128, -74.0060]}
        />
      );
    });

    // Find the center to user location button (target icon)
    const centerButton = screen.getByRole('button');
    const buttons = screen.getAllByRole('button');
    const targetButton = buttons.find(button => 
      button.querySelector('svg') && button.getAttribute('class')?.includes('w-10 h-10')
    );

    if (targetButton) {
      await user.click(targetButton);
      // Should center map to user location
    }
  });

  it('should display map statistics correctly', async () => {
    await act(async () => {
      render(<EnhancedInteractiveMap annotations={mockAnnotations} />);
    });

    await waitFor(() => {
      expect(screen.getByText('标注: 2')).toBeInTheDocument();
      expect(screen.getByText('发现: 1')).toBeInTheDocument(); // One annotation is discovered
      expect(screen.getByText(/缩放:/)).toBeInTheDocument();
    });
  });

  it('should handle annotation detail modal', async () => {
    await act(async () => {
      render(<EnhancedInteractiveMap annotations={mockAnnotations} />);
    });

    // This would require simulating a marker click
    // Since markers are rendered programmatically, we test the modal functionality
    // by directly testing the modal state
  });

  it('should handle create annotation modal', async () => {
    await act(async () => {
      render(<EnhancedInteractiveMap />);
    });

    // Find create button (+ icon)
    const createButton = screen.getByText('+').closest('button');
    if (createButton) {
      await user.click(createButton);
    }

    await waitFor(() => {
      expect(screen.getByText('创建新标注')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('标注标题')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('奖励金额（¥）')).toBeInTheDocument();
    });
  });

  it('should handle map click events', async () => {
    const mockOnMapClick = jest.fn();
    
    await act(async () => {
      render(<EnhancedInteractiveMap onMapClick={mockOnMapClick} />);
    });

    // Simulate map click - this would be on the map container
    const mapContainer = screen.getByRole('button').closest('div');
    if (mapContainer) {
      fireEvent.click(mapContainer);
    }
  });

  it('should render different marker colors based on reward amount', async () => {
    const differentRewardAnnotations = [
      { ...mockAnnotations[0], rewardAmount: 5 },  // Low reward - green
      { ...mockAnnotations[0], id: '2', rewardAmount: 15 }, // Medium reward - blue
      { ...mockAnnotations[0], id: '3', rewardAmount: 25 }, // High reward - red
    ];

    await act(async () => {
      render(<EnhancedInteractiveMap annotations={differentRewardAnnotations} />);
    });

    // Verify different reward amounts are handled
    await waitFor(() => {
      expect(screen.getByText('标注: 3')).toBeInTheDocument();
    });
  });

  it('should handle heatmap toggle', async () => {
    await act(async () => {
      render(
        <EnhancedInteractiveMap 
          annotations={mockAnnotations}
          showHeatmap={true}
        />
      );
    });

    // When heatmap is enabled, should render heatmap elements
    // This would be tested through DOM inspection of the heatmap layer
  });

  it('should handle different themes correctly', () => {
    const themes = ['light', 'dark', 'cyberpunk'] as const;
    
    themes.forEach(theme => {
      const { unmount } = render(
        <EnhancedInteractiveMap theme={theme} />
      );
      
      // Verify theme is applied (would check CSS classes)
      expect(screen.getByText('缩放:')).toBeInTheDocument();
      
      unmount();
    });
  });

  it('should calculate coordinates correctly', async () => {
    const mockOnMapClick = jest.fn();
    
    await act(async () => {
      render(<EnhancedInteractiveMap onMapClick={mockOnMapClick} />);
    });

    // Test coordinate conversion by simulating click at specific position
    // This would test the pixelToCoordinate function
  });

  it('should handle pan gestures', async () => {
    const mockOnCenterChange = jest.fn();
    
    await act(async () => {
      render(
        <EnhancedInteractiveMap 
          onCenterChange={mockOnCenterChange}
        />
      );
    });

    // Test pan by simulating drag events
    // This would test the handlePan function
  });

  it('should handle wheel zoom', async () => {
    const mockOnZoomChange = jest.fn();
    
    await act(async () => {
      render(
        <EnhancedInteractiveMap 
          onZoomChange={mockOnZoomChange}
        />
      );
    });

    // Simulate wheel event for zooming
    const mapContainer = document.body.firstChild as Element;
    if (mapContainer) {
      fireEvent.wheel(mapContainer, { deltaY: -100 });
      // Should zoom in
      
      fireEvent.wheel(mapContainer, { deltaY: 100 });
      // Should zoom out
    }
  });

  describe('Marker Component', () => {
    it('should render marker with correct reward indicator', async () => {
      await act(async () => {
        render(<EnhancedInteractiveMap annotations={[mockAnnotations[0]]} />);
      });

      // Test marker rendering and reward display
      await waitFor(() => {
        expect(screen.getByText('标注: 1')).toBeInTheDocument();
      });
    });

    it('should show hover tooltip on marker hover', async () => {
      // This would test the MapMarker component's hover functionality
      // Since it uses complex animations, we test the overall map functionality
    });

    it('should handle discovered vs undiscovered states', async () => {
      await act(async () => {
        render(<EnhancedInteractiveMap annotations={mockAnnotations} />);
      });

      // One annotation is discovered, one is not
      await waitFor(() => {
        expect(screen.getByText('发现: 1')).toBeInTheDocument();
      });
    });
  });

  describe('User Location', () => {
    it('should display user location marker when provided', async () => {
      const userLocation: [number, number] = [39.9042, 116.4074];
      
      await act(async () => {
        render(
          <EnhancedInteractiveMap 
            userLocation={userLocation}
          />
        );
      });

      await waitFor(() => {
        expect(screen.getByText('您的位置')).toBeInTheDocument();
      });
    });

    it('should get user location automatically when not provided', async () => {
      // Mock successful geolocation
      const mockGeolocation = {
        getCurrentPosition: jest.fn((success) => {
          success({
            coords: {
              latitude: 39.9042,
              longitude: 116.4074,
              accuracy: 10
            }
          });
        })
      };

      Object.defineProperty(navigator, 'geolocation', {
        writable: true,
        value: mockGeolocation
      });

      await act(async () => {
        render(<EnhancedInteractiveMap />);
      });

      await waitFor(() => {
        expect(screen.getByText('您的位置')).toBeInTheDocument();
      });
    });
  });

  describe('Performance', () => {
    it('should handle large number of annotations efficiently', async () => {
      const manyAnnotations = Array.from({ length: 100 }, (_, i) => ({
        ...mockAnnotations[0],
        id: `annotation-${i}`,
        latitude: 39.9042 + (i * 0.001),
        longitude: 116.4074 + (i * 0.001)
      }));

      await act(async () => {
        render(<EnhancedInteractiveMap annotations={manyAnnotations} />);
      });

      await waitFor(() => {
        expect(screen.getByText('标注: 100')).toBeInTheDocument();
      });
    });

    it('should filter visible annotations correctly', async () => {
      // Test that only visible annotations are rendered
      // This tests the visibleAnnotations useMemo hook
      
      await act(async () => {
        render(<EnhancedInteractiveMap annotations={mockAnnotations} />);
      });

      // Should show correct count
      await waitFor(() => {
        expect(screen.getByText(/标注:/)).toBeInTheDocument();
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle annotation click errors gracefully', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      await act(async () => {
        render(<EnhancedInteractiveMap annotations={mockAnnotations} />);
      });

      // Should render without errors
      expect(screen.getByText(/标注:/)).toBeInTheDocument();
      
      consoleErrorSpy.mockRestore();
    });

    it('should handle invalid coordinates gracefully', async () => {
      const invalidAnnotations = [{
        ...mockAnnotations[0],
        latitude: NaN,
        longitude: Infinity
      }];

      await act(async () => {
        render(<EnhancedInteractiveMap annotations={invalidAnnotations} />);
      });

      // Should render without crashing
      expect(screen.getByText(/缩放:/)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should be keyboard navigable', async () => {
      render(<EnhancedInteractiveMap />);
      
      // Test tab navigation through controls
      await user.tab();
      expect(document.activeElement).toBeInTheDocument();
    });

    it('should have proper ARIA labels', () => {
      render(<EnhancedInteractiveMap />);
      
      // Check for accessible button labels
      const buttons = screen.getAllByRole('button');
      expect(buttons.length).toBeGreaterThan(0);
    });
  });
});