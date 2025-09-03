import { Page, expect, Locator } from '@playwright/test';
import { BasePage } from './base-page';

/**
 * 增强版地图页面Page Object
 * 专门用于复杂的地图交互和LBS功能测试
 */
export class EnhancedMapPage extends BasePage {
  // 增强的选择器定义
  private readonly selectors = {
    // 地图容器和核心元素
    mapContainer: '#map, .map-container, [data-testid="map"]',
    mapCanvas: '.leaflet-container, .mapboxgl-canvas, canvas',
    mapOverlay: '.map-overlay, .ui-overlay',
    
    // 标注和标记相关
    annotationMarkers: '.marker, .annotation-marker, [data-testid*="marker"]',
    userLocationMarker: '.current-location, .user-location, [data-testid="user-location"]',
    selectedMarker: '.marker.selected, .annotation-marker.active',
    markerCluster: '.marker-cluster, .cluster',
    
    // 创建标注表单
    createAnnotationModal: '[data-testid="create-annotation-modal"], .create-modal',
    annotationForm: '[data-testid="annotation-form"], .annotation-form',
    titleInput: 'input[name="title"], input[placeholder*="标题"]',
    descriptionTextarea: 'textarea[name="description"], textarea[placeholder*="描述"]',
    categorySelect: 'select[name="category"], [data-testid="category-select"]',
    intensitySlider: '[data-testid="intensity-slider"], .intensity-slider',
    rewardAmountInput: 'input[name="rewardAmount"], input[name="reward"]',
    imageUpload: 'input[type="file"], [data-testid="image-upload"]',
    submitButton: 'button[type="submit"], button:has-text("创建"), button:has-text("提交")',
    cancelButton: 'button:has-text("取消"), [data-testid="cancel-button"]',
    
    // 标注详情弹窗
    annotationDetailModal: '[data-testid="annotation-detail"], .annotation-detail',
    detailTitle: '.annotation-title, [data-testid="annotation-title"]',
    detailDescription: '.annotation-description, [data-testid="annotation-description"]',
    detailAuthor: '.annotation-author, [data-testid="annotation-author"]',
    detailReward: '.reward-amount, [data-testid="reward-amount"]',
    likeButton: 'button:has-text("点赞"), .like-button, [data-testid="like-button"]',
    shareButton: 'button:has-text("分享"), .share-button, [data-testid="share-button"]',
    commentButton: 'button:has-text("评论"), .comment-button, [data-testid="comment-button"]',
    claimRewardButton: 'button:has-text("领取"), .claim-button, [data-testid="claim-reward"]',
    
    // 搜索和筛选
    searchInput: 'input[type="search"], input[placeholder*="搜索"]',
    searchButton: 'button:has-text("搜索"), [data-testid="search-button"]',
    filterButton: 'button:has-text("筛选"), [data-testid="filter-button"]',
    advancedFilterModal: '[data-testid="advanced-filter"], .advanced-filter',
    categoryFilter: '[data-testid="category-filter"]',
    distanceFilter: '[data-testid="distance-filter"]',
    rewardRangeFilter: '[data-testid="reward-range-filter"]',
    dateRangeFilter: '[data-testid="date-range-filter"]',
    applyFilterButton: 'button:has-text("应用"), [data-testid="apply-filter"]',
    clearFilterButton: 'button:has-text("清除"), [data-testid="clear-filter"]',
    
    // 地图控件
    zoomInButton: '.leaflet-control-zoom-in, [data-testid="zoom-in"]',
    zoomOutButton: '.leaflet-control-zoom-out, [data-testid="zoom-out"]',
    fullscreenButton: '.fullscreen-button, [data-testid="fullscreen"]',
    layerSwitcher: '.layer-switcher, [data-testid="layer-switcher"]',
    geolocationButton: '.leaflet-control-locate, [data-testid="locate"]',
    
    // 地图模式切换
    mapModeButtons: '.map-mode-buttons, [data-testid="map-modes"]',
    markersMode: 'button:has-text("标记模式"), [data-testid="markers-mode"]',
    heatmapMode: 'button:has-text("热力图"), [data-testid="heatmap-mode"]',
    hybridMode: 'button:has-text("混合模式"), [data-testid="hybrid-mode"]',
    
    // LBS和奖励相关
    locationTracker: '[data-testid="location-tracker"], .location-tracker',
    geofenceIndicator: '.geofence, .discovery-zone, [data-testid="geofence"]',
    rewardNotification: '.reward-notification, [data-testid="reward-notification"]',
    rewardModal: '[data-testid="reward-modal"], .reward-modal',
    nearbyAnnotations: '[data-testid="nearby-annotations"], .nearby-list',
    
    // 支付相关
    paymentModal: '[data-testid="payment-modal"], .payment-modal',
    paymentForm: '[data-testid="payment-form"], .payment-form',
    cardNumberInput: 'input[name="cardNumber"], input[placeholder*="卡号"]',
    expiryInput: 'input[name="expiry"], input[placeholder*="有效期"]',
    cvcInput: 'input[name="cvc"], input[placeholder*="CVC"]',
    cardHolderInput: 'input[name="name"], input[placeholder*="姓名"]',
    paymentSubmitButton: 'button:has-text("支付"), [data-testid="payment-submit"]',
    
    // 状态和消息
    loadingIndicator: '.loading, .spinner, [data-testid="loading"]',
    errorMessage: '.error, [role="alert"], [data-testid="error"]',
    successMessage: '.success, [data-testid="success"]',
    toastMessage: '.toast, .notification, [data-testid="toast"]',
    
    // 导航和菜单
    topNavigation: '.top-navigation, [data-testid="top-nav"]',
    userMenu: '.user-menu, [data-testid="user-menu"]',
    walletButton: 'button:has-text("钱包"), [data-testid="wallet-button"]',
    profileButton: 'button:has-text("个人资料"), [data-testid="profile-button"]',
  };

  constructor(page: Page) {
    super(page);
  }

  // 等待地图完全加载
  async waitForMapFullyLoaded(): Promise<void> {
    // 等待地图容器出现
    await this.waitForElement(this.selectors.mapContainer);
    
    // 等待地图瓦片加载
    await this.page.waitForFunction(() => {
      const mapElement = document.querySelector('#map, .map-container, [data-testid="map"]');
      if (!mapElement) return false;
      
      // 检查是否有地图实例
      const map = (window as any).map || (window as any).__map__;
      if (map && map._loaded) return true;
      
      // 检查Leaflet地图
      if ((window as any).L && (window as any).L.DomUtil) {
        const tiles = document.querySelectorAll('.leaflet-tile');
        return tiles.length > 0;
      }
      
      return false;
    }, { timeout: 15000 });
    
    // 额外等待以确保交互就绪
    await this.page.waitForTimeout(2000);
  }

  // 智能点击地图位置
  async clickMapLocationSmart(lat: number, lng: number): Promise<void> {
    const mapContainer = await this.waitForElement(this.selectors.mapContainer);
    const mapBounds = await mapContainer.boundingBox();
    
    if (!mapBounds) {
      throw new Error('无法获取地图边界');
    }

    // 计算实际的像素坐标（基于地图中心和缩放级别）
    const centerLat = await this.page.evaluate(() => {
      const map = (window as any).map;
      return map ? map.getCenter().lat : 39.9042; // 默认北京
    });

    const centerLng = await this.page.evaluate(() => {
      const map = (window as any).map;
      return map ? map.getCenter().lng : 116.4074; // 默认北京
    });

    const zoom = await this.page.evaluate(() => {
      const map = (window as any).map;
      return map ? map.getZoom() : 13;
    });

    // 计算相对位置
    const scale = Math.pow(2, zoom - 10); // 基于缩放级别的比例
    const relativeX = (lng - centerLng) * scale * 1000;
    const relativeY = (centerLat - lat) * scale * 1000;

    // 转换为像素坐标
    const pixelX = mapBounds.x + mapBounds.width / 2 + relativeX;
    const pixelY = mapBounds.y + mapBounds.height / 2 + relativeY;

    // 确保点击坐标在地图范围内
    const clampedX = Math.max(mapBounds.x, Math.min(mapBounds.x + mapBounds.width, pixelX));
    const clampedY = Math.max(mapBounds.y, Math.min(mapBounds.y + mapBounds.height, pixelY));

    await this.page.mouse.click(clampedX, clampedY);
    await this.page.waitForTimeout(500);
  }

  // 创建详细标注
  async createDetailedAnnotation(annotationData: {
    title: string;
    description: string;
    category: string;
    intensity: number;
    rewardAmount: number;
    latitude: number;
    longitude: number;
    images?: string[];
  }): Promise<void> {
    // 1. 点击地图位置
    await this.clickMapLocationSmart(annotationData.latitude, annotationData.longitude);
    
    // 2. 等待并点击创建按钮
    await this.waitForElement(this.selectors.createAnnotationModal);
    
    // 3. 填写标注信息
    await this.fillElement(this.selectors.titleInput, annotationData.title);
    await this.fillElement(this.selectors.descriptionTextarea, annotationData.description);
    
    // 4. 选择分类
    if (await this.page.locator(this.selectors.categorySelect).isVisible()) {
      await this.selectOption(this.selectors.categorySelect, annotationData.category);
    }
    
    // 5. 设置强度
    const intensitySlider = this.page.locator(this.selectors.intensitySlider);
    if (await intensitySlider.isVisible()) {
      await intensitySlider.click();
      const sliderBounds = await intensitySlider.boundingBox();
      if (sliderBounds) {
        const x = sliderBounds.x + (sliderBounds.width * annotationData.intensity / 5);
        await this.page.mouse.click(x, sliderBounds.y + sliderBounds.height / 2);
      }
    }
    
    // 6. 设置奖励金额
    if (await this.page.locator(this.selectors.rewardAmountInput).isVisible()) {
      await this.fillElement(this.selectors.rewardAmountInput, annotationData.rewardAmount.toString());
    }
    
    // 7. 上传图片（如果有）
    if (annotationData.images && annotationData.images.length > 0) {
      for (const imagePath of annotationData.images) {
        await this.uploadFile(this.selectors.imageUpload, imagePath);
        await this.page.waitForTimeout(1000);
      }
    }
    
    // 8. 提交表单
    const submitPromise = this.page.waitForResponse(response => 
      response.url().includes('/api/annotations') && response.status() === 201
    );
    
    await this.clickElement(this.selectors.submitButton);
    
    try {
      await submitPromise;
    } catch {
      // 如果API调用失败，等待成功消息或错误处理
      await this.page.waitForTimeout(3000);
    }
  }

  // 高级搜索功能
  async performAdvancedSearch(searchCriteria: {
    keyword?: string;
    category?: string;
    minReward?: number;
    maxReward?: number;
    maxDistance?: number;
    dateFrom?: string;
    dateTo?: string;
  }): Promise<void> {
    // 1. 打开高级筛选
    await this.clickElement(this.selectors.filterButton);
    await this.waitForElement(this.selectors.advancedFilterModal);
    
    // 2. 设置搜索条件
    if (searchCriteria.keyword) {
      await this.fillElement(this.selectors.searchInput, searchCriteria.keyword);
    }
    
    if (searchCriteria.category) {
      await this.selectOption(this.selectors.categoryFilter, searchCriteria.category);
    }
    
    if (searchCriteria.minReward !== undefined || searchCriteria.maxReward !== undefined) {
      const rewardFilter = this.page.locator(this.selectors.rewardRangeFilter);
      if (await rewardFilter.isVisible()) {
        // 设置奖励范围滑块
        const bounds = await rewardFilter.boundingBox();
        if (bounds) {
          if (searchCriteria.minReward !== undefined) {
            const minX = bounds.x + (bounds.width * searchCriteria.minReward / 100);
            await this.page.mouse.click(minX, bounds.y + bounds.height / 2);
          }
          if (searchCriteria.maxReward !== undefined) {
            const maxX = bounds.x + (bounds.width * searchCriteria.maxReward / 100);
            await this.page.mouse.click(maxX, bounds.y + bounds.height / 2);
          }
        }
      }
    }
    
    if (searchCriteria.maxDistance !== undefined) {
      const distanceInput = this.page.locator(this.selectors.distanceFilter);
      if (await distanceInput.isVisible()) {
        await this.fillElement(this.selectors.distanceFilter, searchCriteria.maxDistance.toString());
      }
    }
    
    // 3. 应用筛选
    await this.clickElement(this.selectors.applyFilterButton);
    await this.waitForPageLoad();
  }

  // 模拟地理围栏进入
  async simulateGeofenceEntry(lat: number, lng: number, radius: number = 100): Promise<void> {
    // 1. 更新用户位置到地理围栏边缘
    await this.page.context().setGeolocation({ latitude: lat + 0.001, longitude: lng + 0.001 });
    await this.page.waitForTimeout(1000);
    
    // 2. 移动到地理围栏内部
    await this.page.context().setGeolocation({ latitude: lat, longitude: lng });
    
    // 3. 触发位置更新事件
    await this.page.evaluate(() => {
      // 触发自定义位置更新事件
      window.dispatchEvent(new CustomEvent('locationupdate', {
        detail: { latitude: lat, longitude: lng }
      }));
      
      // 触发原生地理位置事件
      if (navigator.geolocation) {
        const event = new Event('geolocationchange');
        window.dispatchEvent(event);
      }
    });
    
    await this.page.waitForTimeout(2000);
  }

  // 验证奖励发现和领取
  async verifyAndClaimReward(expectedAmount: number): Promise<void> {
    // 1. 等待奖励通知出现
    await this.waitForElement(this.selectors.rewardNotification, { timeout: 10000 });
    
    // 2. 验证奖励金额
    const rewardElement = this.page.locator(this.selectors.detailReward);
    await expect(rewardElement).toContainText(expectedAmount.toString());
    
    // 3. 点击领取奖励
    const claimButton = this.page.locator(this.selectors.claimRewardButton);
    if (await claimButton.isVisible()) {
      const claimPromise = this.page.waitForResponse(response => 
        response.url().includes('/api/rewards/claim')
      );
      
      await claimButton.click();
      
      try {
        await claimPromise;
      } catch {
        // 如果API调用失败，等待成功消息
        await this.page.waitForTimeout(3000);
      }
    }
    
    // 4. 验证领取成功消息
    await this.verifyToastMessage('奖励已领取|领取成功');
  }

  // 测试支付流程
  async simulatePaymentFlow(paymentData: {
    cardNumber: string;
    expiry: string;
    cvc: string;
    name: string;
    amount: number;
  }): Promise<void> {
    // 1. 等待支付模态框出现
    await this.waitForElement(this.selectors.paymentModal);
    
    // 2. 填写支付信息
    await this.fillElement(this.selectors.cardNumberInput, paymentData.cardNumber);
    await this.fillElement(this.selectors.expiryInput, paymentData.expiry);
    await this.fillElement(this.selectors.cvcInput, paymentData.cvc);
    await this.fillElement(this.selectors.cardHolderInput, paymentData.name);
    
    // 3. 提交支付
    const paymentPromise = this.page.waitForResponse(response => 
      response.url().includes('/api/payments') || response.url().includes('stripe.com')
    );
    
    await this.clickElement(this.selectors.paymentSubmitButton);
    
    try {
      await paymentPromise;
    } catch {
      // 如果没有真实的支付API，等待模拟响应
      await this.page.waitForTimeout(3000);
    }
  }

  // 验证地图标记聚类
  async verifyMarkerClustering(expectedClusterCount: number): Promise<void> {
    const clusters = this.page.locator(this.selectors.markerCluster);
    await expect(clusters).toHaveCount(expectedClusterCount);
    
    // 点击一个聚类来展开
    if (expectedClusterCount > 0) {
      await clusters.first().click();
      await this.page.waitForTimeout(1000);
      
      // 验证聚类展开后显示个别标记
      const individualMarkers = this.page.locator(this.selectors.annotationMarkers);
      await expect(individualMarkers.first()).toBeVisible();
    }
  }

  // 测试地图平移和缩放
  async testMapPanAndZoom(): Promise<void> {
    const mapContainer = await this.waitForElement(this.selectors.mapContainer);
    const bounds = await mapContainer.boundingBox();
    
    if (!bounds) return;
    
    // 1. 测试平移
    const startX = bounds.x + bounds.width / 2;
    const startY = bounds.y + bounds.height / 2;
    const endX = startX + 100;
    const endY = startY + 100;
    
    await this.page.mouse.move(startX, startY);
    await this.page.mouse.down();
    await this.page.mouse.move(endX, endY, { steps: 10 });
    await this.page.mouse.up();
    await this.page.waitForTimeout(1000);
    
    // 2. 测试缩放
    await this.page.mouse.move(startX, startY);
    await this.page.mouse.wheel(0, -100); // 放大
    await this.page.waitForTimeout(1000);
    await this.page.mouse.wheel(0, 100);  // 缩小
    await this.page.waitForTimeout(1000);
  }

  // 验证响应式地图行为
  async verifyResponsiveMapBehavior(viewportWidth: number): Promise<void> {
    if (viewportWidth <= 768) {
      // 移动端验证
      await expect(this.page.locator('.mobile-controls')).toBeVisible();
      await expect(this.page.locator('.desktop-only')).toBeHidden();
    } else {
      // 桌面端验证
      await expect(this.page.locator('.desktop-controls')).toBeVisible();
      await expect(this.page.locator('.mobile-only')).toBeHidden();
    }
  }

  // 获取地图性能指标
  async getMapPerformanceMetrics(): Promise<any> {
    return await this.page.evaluate(() => {
      const performance = window.performance;
      const entries = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      
      return {
        domContentLoaded: entries.domContentLoadedEventEnd - entries.domContentLoadedEventStart,
        loadComplete: entries.loadEventEnd - entries.loadEventStart,
        firstPaint: performance.getEntriesByName('first-paint')[0]?.startTime || 0,
        firstContentfulPaint: performance.getEntriesByName('first-contentful-paint')[0]?.startTime || 0,
        mapTileLoadTime: (window as any).__mapTileLoadTime__ || 0,
        annotationRenderTime: (window as any).__annotationRenderTime__ || 0
      };
    });
  }

  // 模拟网络状态变化
  async simulateNetworkChange(condition: 'online' | 'offline' | 'slow'): Promise<void> {
    switch (condition) {
      case 'offline':
        await this.page.context().setOffline(true);
        break;
      case 'online':
        await this.page.context().setOffline(false);
        break;
      case 'slow':
        await this.page.route('**/*', route => {
          setTimeout(() => {
            route.continue();
          }, 2000); // 2秒延迟模拟慢网络
        });
        break;
    }
    
    await this.page.waitForTimeout(1000);
  }

  // 验证错误恢复机制
  async verifyErrorRecovery(): Promise<void> {
    // 检查重试按钮
    const retryButton = this.page.locator('button:has-text("重试"), .retry-button');
    if (await retryButton.isVisible()) {
      await retryButton.click();
      await this.page.waitForTimeout(2000);
    }
    
    // 检查错误消息是否消失
    const errorMessage = this.page.locator(this.selectors.errorMessage);
    await expect(errorMessage).toBeHidden();
  }
}