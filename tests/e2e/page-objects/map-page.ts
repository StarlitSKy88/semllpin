import { Page, expect } from '@playwright/test';
import { BasePage } from './base-page';

export class MapPage extends BasePage {
  private readonly selectors = {
    // 地图相关
    mapContainer: '#map, .map-container, [data-testid="map"]',
    mapCanvas: '.leaflet-container, .mapboxgl-canvas, canvas',
    
    // 标注创建
    createAnnotationButton: 'button:has-text("创建标注"), button:has-text("Add Annotation"), [data-testid="create-annotation"]',
    annotationForm: '[data-testid="annotation-form"], .annotation-form',
    titleInput: 'input[name="title"], input[placeholder*="标题"]',
    descriptionInput: 'textarea[name="description"], textarea[placeholder*="描述"]',
    categorySelect: 'select[name="category"], [data-testid="category-select"]',
    smellIntensity: 'input[name="intensity"], [data-testid="intensity-slider"]',
    rewardAmount: 'input[name="reward"], input[name="rewardAmount"]',
    mediaUpload: 'input[type="file"], [data-testid="media-upload"]',
    submitButton: 'button[type="submit"], button:has-text("提交"), button:has-text("Submit")',
    
    // 标注详情
    annotationMarker: '.marker, .annotation-marker, [data-testid*="marker"]',
    annotationPopup: '.popup, .annotation-popup, [role="tooltip"]',
    annotationTitle: '.annotation-title, .popup-title',
    annotationDescription: '.annotation-description, .popup-description',
    likeButton: 'button:has-text("点赞"), button[aria-label*="like"], .like-button',
    commentButton: 'button:has-text("评论"), button[aria-label*="comment"], .comment-button',
    shareButton: 'button:has-text("分享"), button[aria-label*="share"], .share-button',
    
    // 搜索和筛选
    searchInput: 'input[placeholder*="搜索"], input[type="search"]',
    filterButton: 'button:has-text("筛选"), button:has-text("Filter")',
    categoryFilter: '[data-testid="category-filter"]',
    distanceFilter: '[data-testid="distance-filter"]',
    
    // 用户位置
    locationButton: 'button[aria-label*="location"], .location-btn, [data-testid="location"]',
    currentLocationMarker: '.current-location, .user-location',
    
    // 奖励发现
    discoveryNotification: '.discovery-notification, [data-testid="discovery"]',
    rewardAmount: '.reward-amount, [data-testid="reward-amount"]',
    claimRewardButton: 'button:has-text("领取"), button:has-text("Claim")',
    
    // 地理围栏
    geofenceRadius: '.geofence, .discovery-zone',
    
    // 加载状态
    loadingSpinner: '.loading, .spinner, [data-testid="loading"]',
    
    // 错误状态
    errorMessage: '.error, [role="alert"]',
    locationPermissionError: '.location-error, [data-testid="location-error"]',
  };

  constructor(page: Page) {
    super(page);
  }

  // 导航到地图页面
  async navigateToMap() {
    await this.navigateTo('/map');
    await this.waitForPageLoad();
    await this.waitForMapLoad();
  }

  // 等待地图加载完成
  async waitForMapLoad() {
    await this.waitForElement(this.selectors.mapContainer);
    
    // 等待地图瓦片加载
    await this.page.waitForTimeout(2000);
    
    // 等待loading spinner消失
    await this.page.locator(this.selectors.loadingSpinner).waitFor({ 
      state: 'hidden',
      timeout: 10000 
    }).catch(() => {
      // 如果没有loading spinner，继续执行
    });
  }

  // 创建新标注
  async createAnnotation(annotationData: {
    title: string;
    description: string;
    category: string;
    intensity: number;
    rewardAmount: number;
    latitude: number;
    longitude: number;
    mediaFile?: string;
  }) {
    // 点击地图上的特定位置
    await this.clickMapLocation(annotationData.latitude, annotationData.longitude);
    
    // 等待创建标注按钮出现并点击
    await this.clickElement(this.selectors.createAnnotationButton);
    
    // 等待表单出现
    await this.waitForElement(this.selectors.annotationForm);
    
    // 填写表单
    await this.fillElement(this.selectors.titleInput, annotationData.title);
    await this.fillElement(this.selectors.descriptionInput, annotationData.description);
    await this.selectOption(this.selectors.categorySelect, annotationData.category);
    
    // 设置强度
    const intensitySlider = this.page.locator(this.selectors.smellIntensity);
    await intensitySlider.fill(annotationData.intensity.toString());
    
    // 设置奖励金额
    await this.fillElement(this.selectors.rewardAmount, annotationData.rewardAmount.toString());
    
    // 上传媒体文件
    if (annotationData.mediaFile) {
      await this.uploadFile(this.selectors.mediaUpload, annotationData.mediaFile);
    }
    
    // 监听创建API请求
    const createResponsePromise = this.page.waitForResponse(
      response => response.url().includes('/api/annotations') && response.status() === 201
    );
    
    // 提交表单
    await this.clickElement(this.selectors.submitButton);
    
    // 等待创建成功
    await createResponsePromise;
    await this.waitForPageLoad();
  }

  // 点击地图上的特定位置
  async clickMapLocation(latitude: number, longitude: number) {
    const mapContainer = await this.waitForElement(this.selectors.mapContainer);
    
    // 计算地图上的像素坐标（简化处理）
    const mapBounds = await mapContainer.boundingBox();
    if (!mapBounds) throw new Error('无法获取地图边界');
    
    // 点击地图中心位置（简化处理）
    const x = mapBounds.x + mapBounds.width / 2;
    const y = mapBounds.y + mapBounds.height / 2;
    
    await this.page.mouse.click(x, y);
    await this.page.waitForTimeout(500); // 等待点击处理
  }

  // 搜索标注
  async searchAnnotations(query: string) {
    await this.fillElement(this.selectors.searchInput, query);
    await this.page.keyboard.press('Enter');
    await this.waitForPageLoad();
  }

  // 筛选标注
  async filterAnnotations(filters: {
    category?: string;
    maxDistance?: number;
  }) {
    await this.clickElement(this.selectors.filterButton);
    
    if (filters.category) {
      await this.selectOption(this.selectors.categoryFilter, filters.category);
    }
    
    if (filters.maxDistance) {
      await this.fillElement(this.selectors.distanceFilter, filters.maxDistance.toString());
    }
    
    // 应用筛选
    await this.page.keyboard.press('Enter');
    await this.waitForPageLoad();
  }

  // 点击标注marker
  async clickAnnotationMarker(index = 0) {
    const markers = this.page.locator(this.selectors.annotationMarker);
    await markers.nth(index).click();
    
    // 等待弹窗出现
    await this.waitForElement(this.selectors.annotationPopup);
  }

  // 验证标注详情
  async verifyAnnotationDetails(expectedData: {
    title: string;
    description: string;
  }) {
    const popup = this.page.locator(this.selectors.annotationPopup);
    await expect(popup).toBeVisible();
    
    const titleElement = popup.locator(this.selectors.annotationTitle);
    await expect(titleElement).toContainText(expectedData.title);
    
    const descriptionElement = popup.locator(this.selectors.annotationDescription);
    await expect(descriptionElement).toContainText(expectedData.description);
  }

  // 点赞标注
  async likeAnnotation() {
    await this.clickElement(this.selectors.likeButton);
    
    // 等待API响应
    await this.waitForAPI('/api/annotations/like');
    
    // 验证点赞状态
    const likeButton = this.page.locator(this.selectors.likeButton);
    await expect(likeButton).toHaveClass(/liked|active/);
  }

  // 获取当前位置
  async getCurrentLocation() {
    await this.clickElement(this.selectors.locationButton);
    
    // 等待定位完成
    await this.page.waitForTimeout(2000);
    
    // 验证当前位置marker出现
    await expect(this.page.locator(this.selectors.currentLocationMarker)).toBeVisible();
  }

  // 模拟进入地理围栏
  async enterGeofence(latitude: number, longitude: number) {
    // 更新地理位置
    await this.page.context().setGeolocation({ latitude, longitude });
    
    // 触发位置更新事件
    await this.page.evaluate(() => {
      window.dispatchEvent(new Event('locationupdate'));
    });
    
    // 等待发现通知
    await this.waitForElement(this.selectors.discoveryNotification);
  }

  // 验证奖励发现
  async verifyRewardDiscovery(expectedAmount: number) {
    const notification = this.page.locator(this.selectors.discoveryNotification);
    await expect(notification).toBeVisible();
    
    const rewardAmountElement = notification.locator(this.selectors.rewardAmount);
    await expect(rewardAmountElement).toContainText(expectedAmount.toString());
  }

  // 领取奖励
  async claimReward() {
    await this.clickElement(this.selectors.claimRewardButton);
    
    // 等待API响应
    await this.waitForAPI('/api/rewards/claim');
    
    // 验证奖励已领取
    await this.verifyToastMessage('奖励已领取');
  }

  // 验证地图上的标注数量
  async verifyAnnotationCount(expectedCount: number) {
    const markers = this.page.locator(this.selectors.annotationMarker);
    await expect(markers).toHaveCount(expectedCount);
  }

  // 验证位置权限错误
  async verifyLocationPermissionError() {
    const errorElement = this.page.locator(this.selectors.locationPermissionError);
    await expect(errorElement).toBeVisible();
    await expect(errorElement).toContainText(/位置|permission|location/i);
  }

  // 等待地图交互就绪
  async waitForMapInteraction() {
    // 等待地图容器加载
    await this.waitForElement(this.selectors.mapContainer);
    
    // 等待地图瓦片和交互就绪
    await this.page.waitForFunction(() => {
      const map = (window as any).map;
      return map && map._loaded;
    }, { timeout: 15000 }).catch(() => {
      // 如果没有全局map对象，等待固定时间
      return this.page.waitForTimeout(3000);
    });
  }
}