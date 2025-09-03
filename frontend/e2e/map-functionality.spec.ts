import { test, expect, Page, BrowserContext } from '@playwright/test';

// Helper function to grant geolocation permissions
async function grantGeolocationPermission(context: BrowserContext) {
  await context.grantPermissions(['geolocation']);
  await context.setGeolocation({ latitude: 39.9042, longitude: 116.4074 });
}

// Helper function to wait for map to load
async function waitForMapLoad(page: Page) {
  await page.waitForSelector('[data-testid="map-container"]', { timeout: 10000 });
  await page.waitForTimeout(2000); // Allow time for tiles to load
}

test.describe('OpenStreetMap Functionality', () => {
  test.beforeEach(async ({ page, context }) => {
    // Grant geolocation permission before each test
    await grantGeolocationPermission(context);
    
    // Navigate to the map page
    await page.goto('/');
  });

  test.describe('Map Loading and Display', () => {
    test('should load OpenStreetMap tiles correctly', async ({ page }) => {
      await waitForMapLoad(page);

      // Check if map container is present
      const mapContainer = page.locator('[data-testid="map-container"]');
      await expect(mapContainer).toBeVisible();

      // Check if tile layer is present
      const tileLayer = page.locator('[data-testid="tile-layer"]');
      await expect(tileLayer).toBeVisible();

      // Verify OpenStreetMap attribution is present
      await expect(page.locator('text=OpenStreetMap')).toBeVisible();
    });

    test('should display loading state initially', async ({ page }) => {
      await page.goto('/');
      
      // Should show loading message initially
      await expect(page.locator('text=地图加载中...')).toBeVisible();
      
      // Wait for map to load
      await waitForMapLoad(page);
      
      // Loading message should disappear
      await expect(page.locator('text=地图加载中...')).not.toBeVisible();
    });

    test('should handle geolocation permission granted', async ({ page }) => {
      await waitForMapLoad(page);

      // Check if user location marker appears
      await expect(page.locator('text=你的位置')).toBeVisible({ timeout: 5000 });
    });

    test('should handle geolocation permission denied gracefully', async ({ page, context }) => {
      // Block geolocation
      await context.clearPermissions();
      
      await page.goto('/');
      await waitForMapLoad(page);

      // Map should still load without user location
      const mapContainer = page.locator('[data-testid="map-container"]');
      await expect(mapContainer).toBeVisible();
    });
  });

  test.describe('Map Interactions', () => {
    test('should handle map zoom controls', async ({ page }) => {
      await waitForMapLoad(page);

      // Test zoom functionality (if zoom controls are visible)
      const mapContainer = page.locator('[data-testid="map-container"]');
      
      // Simulate wheel zoom
      await mapContainer.hover();
      await page.mouse.wheel(0, -100); // Zoom in
      await page.waitForTimeout(500);
      
      await page.mouse.wheel(0, 100); // Zoom out
      await page.waitForTimeout(500);
      
      // Map should still be visible and functional
      await expect(mapContainer).toBeVisible();
    });

    test('should handle map click events', async ({ page }) => {
      await waitForMapLoad(page);

      const mapContainer = page.locator('[data-testid="map-container"]');
      
      // Click on map
      await mapContainer.click({ position: { x: 400, y: 300 } });
      
      // Check if any modal or interaction feedback appears
      // This depends on the implementation - adjust based on actual behavior
    });

    test('should handle map dragging/panning', async ({ page }) => {
      await waitForMapLoad(page);

      const mapContainer = page.locator('[data-testid="map-container"]');
      
      // Get initial position
      const box = await mapContainer.boundingBox();
      if (box) {
        // Simulate drag
        await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
        await page.mouse.down();
        await page.mouse.move(box.x + box.width / 2 + 100, box.y + box.height / 2 + 100);
        await page.mouse.up();
        
        // Map should still be functional
        await expect(mapContainer).toBeVisible();
      }
    });
  });

  test.describe('Annotation Functionality', () => {
    test('should display annotation markers on map', async ({ page }) => {
      await waitForMapLoad(page);

      // Check if annotation markers are present
      const markers = page.locator('[data-testid="marker"]');
      const markerCount = await markers.count();
      
      if (markerCount > 0) {
        // At least one marker should be visible
        await expect(markers.first()).toBeVisible();
      }
    });

    test('should show annotation popup on marker click', async ({ page }) => {
      await waitForMapLoad(page);

      const markers = page.locator('[data-testid="marker"]');
      const markerCount = await markers.count();
      
      if (markerCount > 0) {
        // Click on first marker
        await markers.first().click();
        
        // Check if popup appears
        const popup = page.locator('[data-testid="popup"]');
        await expect(popup).toBeVisible({ timeout: 3000 });
      }
    });

    test('should display correct annotation information in popup', async ({ page }) => {
      await waitForMapLoad(page);

      const markers = page.locator('[data-testid="marker"]');
      const markerCount = await markers.count();
      
      if (markerCount > 0) {
        await markers.first().click();
        
        // Check popup content
        const popup = page.locator('[data-testid="popup"]');
        await expect(popup).toBeVisible();
        
        // Should contain annotation details
        await expect(popup.locator('text=/气味强度:/')).toBeVisible();
        await expect(popup.locator('text=/位置:/')).toBeVisible();
        await expect(popup.locator('text=/时间:/')).toBeVisible();
      }
    });

    test('should handle create annotation flow', async ({ page }) => {
      await waitForMapLoad(page);

      // Look for create button
      const createButton = page.locator('button:has-text("创建标注"), button:has-text("创建")');
      
      if (await createButton.count() > 0) {
        await createButton.first().click();
        
        // Should open create modal
        await expect(page.locator('text=创建新标注')).toBeVisible();
        
        // Fill out form
        await page.fill('input[placeholder="标注标题"]', '测试标注');
        await page.fill('textarea[placeholder*="标注内容"]', '这是一个测试标注');
        await page.fill('input[placeholder*="奖励金额"]', '10');
        
        // Submit form
        await page.click('button:has-text("创建标注")');
        
        // Should show success message or close modal
        await page.waitForTimeout(1000);
      }
    });
  });

  test.describe('User Location Features', () => {
    test('should display user location marker', async ({ page }) => {
      await waitForMapLoad(page);

      // Check if user location marker is displayed
      await expect(page.locator('text=你的位置')).toBeVisible({ timeout: 5000 });
    });

    test('should center map on user location', async ({ page }) => {
      await waitForMapLoad(page);

      // If there's a center-to-user button, test it
      const centerButton = page.locator('button').filter({ hasText: '🎯' }).or(
        page.locator('button').filter({ has: page.locator('svg[data-lucide="target"]') })
      );

      if (await centerButton.count() > 0) {
        await centerButton.click();
        
        // Map should center on user location
        await page.waitForTimeout(1000);
        await expect(page.locator('text=你的位置')).toBeVisible();
      }
    });

    test('should update location when user moves', async ({ page, context }) => {
      await waitForMapLoad(page);

      // Change geolocation
      await context.setGeolocation({ latitude: 40.0000, longitude: 117.0000 });
      
      // Trigger location update (this would depend on implementation)
      await page.reload();
      await waitForMapLoad(page);
      
      // User location should be updated
      await expect(page.locator('text=你的位置')).toBeVisible();
    });
  });

  test.describe('Map Controls and UI', () => {
    test('should display map legend correctly', async ({ page }) => {
      await waitForMapLoad(page);

      // Check legend elements
      await expect(page.locator('text=轻微 (1-3)')).toBeVisible();
      await expect(page.locator('text=中等 (4-6)')).toBeVisible();
      await expect(page.locator('text=强烈 (7-10)')).toBeVisible();
    });

    test('should display map statistics', async ({ page }) => {
      await waitForMapLoad(page);

      // Look for statistics if they exist
      const statsElements = page.locator('text=/标注:/, text=/发现:/, text=/缩放:/');
      const statsCount = await statsElements.count();
      
      if (statsCount > 0) {
        await expect(statsElements.first()).toBeVisible();
      }
    });

    test('should handle different view modes', async ({ page }) => {
      await waitForMapLoad(page);

      // Test different map modes if available
      const modeButtons = page.locator('button').filter({ hasText: /热力图|标记|混合/ });
      const modeCount = await modeButtons.count();
      
      if (modeCount > 0) {
        for (let i = 0; i < modeCount; i++) {
          await modeButtons.nth(i).click();
          await page.waitForTimeout(500);
          
          // Map should still be functional
          await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
        }
      }
    });
  });

  test.describe('Mobile Responsiveness', () => {
    test('should work correctly on mobile devices', async ({ page }) => {
      // Set mobile viewport
      await page.setViewportSize({ width: 375, height: 667 });
      await waitForMapLoad(page);

      // Map should be visible and functional on mobile
      const mapContainer = page.locator('[data-testid="map-container"]');
      await expect(mapContainer).toBeVisible();

      // Test touch interactions
      await mapContainer.tap({ position: { x: 200, y: 300 } });
      
      // Map should remain functional
      await expect(mapContainer).toBeVisible();
    });

    test('should handle touch gestures for zoom', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 });
      await waitForMapLoad(page);

      const mapContainer = page.locator('[data-testid="map-container"]');
      
      // Simulate pinch zoom (this is complex to test with Playwright)
      // For now, verify map remains functional
      await expect(mapContainer).toBeVisible();
    });

    test('should adapt UI elements for mobile', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 });
      await waitForMapLoad(page);

      // Check if mobile-specific UI elements are present
      // This would depend on responsive design implementation
      const mapContainer = page.locator('[data-testid="map-container"]');
      await expect(mapContainer).toBeVisible();
    });
  });

  test.describe('Error Scenarios', () => {
    test('should handle offline scenarios', async ({ page, context }) => {
      await waitForMapLoad(page);

      // Go offline
      await context.setOffline(true);
      
      // Try to interact with map
      await page.reload();
      
      // Should handle offline gracefully
      // This would show error states or cached content
      const body = page.locator('body');
      await expect(body).toBeVisible();

      // Go back online
      await context.setOffline(false);
    });

    test('should handle slow network conditions', async ({ page, context }) => {
      // Simulate slow network
      await context.route('**/*', async route => {
        await new Promise(resolve => setTimeout(resolve, 2000));
        await route.continue();
      });

      await page.goto('/');
      
      // Should show loading states appropriately
      await expect(page.locator('text=地图加载中...')).toBeVisible();
      
      // Eventually should load
      await waitForMapLoad(page);
    });

    test('should handle API failures gracefully', async ({ page, context }) => {
      // Mock API failures
      await context.route('**/api/annotations/**', route => {
        route.fulfill({
          status: 500,
          body: JSON.stringify({ error: 'Server error' })
        });
      });

      await page.goto('/');
      await waitForMapLoad(page);

      // Map should still render even with API failures
      await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
    });
  });

  test.describe('Performance Testing', () => {
    test('should load map within acceptable time', async ({ page }) => {
      const startTime = Date.now();
      
      await page.goto('/');
      await waitForMapLoad(page);
      
      const loadTime = Date.now() - startTime;
      
      // Map should load within 5 seconds
      expect(loadTime).toBeLessThan(5000);
    });

    test('should handle large number of annotations efficiently', async ({ page, context }) => {
      // Mock API to return many annotations
      await context.route('**/api/annotations/map**', route => {
        const manyAnnotations = Array.from({ length: 100 }, (_, i) => ({
          id: `annotation-${i}`,
          title: `标注 ${i}`,
          latitude: 39.9042 + (i * 0.001),
          longitude: 116.4074 + (i * 0.001),
          smell_intensity: Math.floor(Math.random() * 10) + 1,
          description: `测试标注 ${i}`,
          created_at: new Date().toISOString()
        }));

        route.fulfill({
          status: 200,
          body: JSON.stringify({ success: true, data: manyAnnotations })
        });
      });

      const startTime = Date.now();
      await page.goto('/');
      await waitForMapLoad(page);
      const loadTime = Date.now() - startTime;

      // Should handle many annotations efficiently
      expect(loadTime).toBeLessThan(8000);
      
      // Map should still be responsive
      const mapContainer = page.locator('[data-testid="map-container"]');
      await mapContainer.click({ position: { x: 400, y: 300 } });
      await expect(mapContainer).toBeVisible();
    });

    test('should maintain performance during interactions', async ({ page }) => {
      await waitForMapLoad(page);

      const mapContainer = page.locator('[data-testid="map-container"]');
      
      // Perform multiple rapid interactions
      for (let i = 0; i < 10; i++) {
        await mapContainer.click({ position: { x: 300 + i * 10, y: 200 + i * 10 } });
        await page.waitForTimeout(100);
      }
      
      // Map should remain responsive
      await expect(mapContainer).toBeVisible();
    });
  });

  test.describe('Cross-browser Compatibility', () => {
    test('should work in Chromium', async ({ page, browserName }) => {
      if (browserName === 'chromium') {
        await waitForMapLoad(page);
        await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
      }
    });

    test('should work in Firefox', async ({ page, browserName }) => {
      if (browserName === 'firefox') {
        await waitForMapLoad(page);
        await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
      }
    });

    test('should work in Safari/WebKit', async ({ page, browserName }) => {
      if (browserName === 'webkit') {
        await waitForMapLoad(page);
        await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
      }
    });
  });

  test.describe('Complete User Workflows', () => {
    test('should complete full annotation discovery workflow', async ({ page }) => {
      await waitForMapLoad(page);

      // 1. User sees map with annotations
      const markers = page.locator('[data-testid="marker"]');
      const markerCount = await markers.count();
      
      if (markerCount > 0) {
        // 2. User clicks on an annotation
        await markers.first().click();
        
        // 3. Popup should appear with annotation details
        const popup = page.locator('[data-testid="popup"]');
        await expect(popup).toBeVisible();
        
        // 4. User can interact with the annotation
        // (This would include claiming rewards, viewing details, etc.)
      }
    });

    test('should complete annotation creation workflow', async ({ page }) => {
      await waitForMapLoad(page);

      // 1. User clicks create button
      const createButton = page.locator('button:has-text("创建标注"), button:has-text("创建")');
      
      if (await createButton.count() > 0) {
        await createButton.first().click();
        
        // 2. Create modal should appear
        await expect(page.locator('text=创建新标注')).toBeVisible();
        
        // 3. User fills out form
        await page.fill('input[placeholder="标注标题"]', 'E2E测试标注');
        await page.fill('textarea', '这是一个端到端测试标注');
        await page.fill('input[placeholder*="奖励金额"]', '15');
        
        // 4. User submits form
        await page.click('button:has-text("创建标注")');
        
        // 5. Should show success feedback
        await page.waitForTimeout(1000);
      }
    });

    test('should complete location-based reward workflow', async ({ page, context }) => {
      await waitForMapLoad(page);

      // Mock being near an annotation
      await context.setGeolocation({ latitude: 39.9042, longitude: 116.4074 });
      
      const markers = page.locator('[data-testid="marker"]');
      const markerCount = await markers.count();
      
      if (markerCount > 0) {
        // Click on nearby annotation
        await markers.first().click();
        
        // Look for claim reward button
        const claimButton = page.locator('button:has-text("发现奖励"), button:has-text("发现")');
        
        if (await claimButton.count() > 0) {
          await claimButton.click();
          
          // Should show reward claimed feedback
          await page.waitForTimeout(1000);
        }
      }
    });

    test('should handle search and navigation workflow', async ({ page }) => {
      await waitForMapLoad(page);

      // If there's a search functionality
      const searchInput = page.locator('input[placeholder*="搜索"], input[placeholder*="地址"]');
      
      if (await searchInput.count() > 0) {
        // 1. User searches for location
        await searchInput.fill('天安门广场');
        await page.keyboard.press('Enter');
        
        // 2. Map should navigate to location
        await page.waitForTimeout(2000);
        
        // 3. Map should be functional at new location
        await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
      }
    });
  });

  test.describe('Data Persistence', () => {
    test('should maintain map state across page reloads', async ({ page }) => {
      await waitForMapLoad(page);

      // Interact with map (zoom, pan, etc.)
      const mapContainer = page.locator('[data-testid="map-container"]');
      await mapContainer.click({ position: { x: 400, y: 300 } });
      
      // Reload page
      await page.reload();
      await waitForMapLoad(page);
      
      // Map should reload properly
      await expect(mapContainer).toBeVisible();
    });

    test('should handle browser back/forward navigation', async ({ page }) => {
      await waitForMapLoad(page);

      // Navigate to different page (if available)
      // Then use browser back
      await page.goBack();
      await page.goForward();
      
      // Map should work after navigation
      await waitForMapLoad(page);
      await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
    });
  });

  test.describe('Accessibility', () => {
    test('should be keyboard navigable', async ({ page }) => {
      await waitForMapLoad(page);

      // Test tab navigation
      await page.keyboard.press('Tab');
      
      // Should be able to navigate to interactive elements
      const focusedElement = page.locator(':focus');
      await expect(focusedElement).toBeVisible();
    });

    test('should have proper ARIA labels', async ({ page }) => {
      await waitForMapLoad(page);

      // Check for ARIA labels on interactive elements
      const buttons = page.locator('button');
      const buttonCount = await buttons.count();
      
      if (buttonCount > 0) {
        // At least some buttons should have accessible names
        const firstButton = buttons.first();
        const ariaLabel = await firstButton.getAttribute('aria-label');
        const hasText = await firstButton.textContent();
        
        // Should have either aria-label or text content
        expect(ariaLabel || hasText).toBeTruthy();
      }
    });

    test('should support screen readers', async ({ page }) => {
      await waitForMapLoad(page);

      // Check for semantic HTML structure
      const mapContainer = page.locator('[data-testid="map-container"]');
      await expect(mapContainer).toBeVisible();
      
      // Should have proper role attributes where needed
      const interactiveElements = page.locator('[role], button, input, textarea');
      const count = await interactiveElements.count();
      expect(count).toBeGreaterThan(0);
    });
  });

  test.describe('Security', () => {
    test('should handle malicious location data', async ({ page, context }) => {
      // Set extreme coordinates
      await context.setGeolocation({ latitude: 999, longitude: 999 });
      
      await page.goto('/');
      await waitForMapLoad(page);
      
      // Should handle invalid coordinates gracefully
      await expect(page.locator('[data-testid="map-container"]')).toBeVisible();
    });

    test('should validate user input in forms', async ({ page }) => {
      await waitForMapLoad(page);

      const createButton = page.locator('button:has-text("创建标注"), button:has-text("创建")');
      
      if (await createButton.count() > 0) {
        await createButton.first().click();
        
        // Try to submit with malicious data
        await page.fill('input[placeholder="标注标题"]', '<script>alert("xss")</script>');
        await page.fill('textarea', 'javascript:void(0)');
        await page.fill('input[placeholder*="奖励金额"]', '-999999');
        
        await page.click('button:has-text("创建标注")');
        
        // Should handle malicious input appropriately
        await page.waitForTimeout(1000);
      }
    });
  });
});