"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MapPage = void 0;
const test_1 = require("@playwright/test");
const base_page_1 = require("./base-page");
class MapPage extends base_page_1.BasePage {
    constructor(page) {
        super(page);
        this.selectors = {
            mapContainer: '#map, .map-container, [data-testid="map"]',
            mapCanvas: '.leaflet-container, .mapboxgl-canvas, canvas',
            createAnnotationButton: 'button:has-text("创建标注"), button:has-text("Add Annotation"), [data-testid="create-annotation"]',
            annotationForm: '[data-testid="annotation-form"], .annotation-form',
            titleInput: 'input[name="title"], input[placeholder*="标题"]',
            descriptionInput: 'textarea[name="description"], textarea[placeholder*="描述"]',
            categorySelect: 'select[name="category"], [data-testid="category-select"]',
            smellIntensity: 'input[name="intensity"], [data-testid="intensity-slider"]',
            rewardAmount: 'input[name="reward"], input[name="rewardAmount"]',
            mediaUpload: 'input[type="file"], [data-testid="media-upload"]',
            submitButton: 'button[type="submit"], button:has-text("提交"), button:has-text("Submit")',
            annotationMarker: '.marker, .annotation-marker, [data-testid*="marker"]',
            annotationPopup: '.popup, .annotation-popup, [role="tooltip"]',
            annotationTitle: '.annotation-title, .popup-title',
            annotationDescription: '.annotation-description, .popup-description',
            likeButton: 'button:has-text("点赞"), button[aria-label*="like"], .like-button',
            commentButton: 'button:has-text("评论"), button[aria-label*="comment"], .comment-button',
            shareButton: 'button:has-text("分享"), button[aria-label*="share"], .share-button',
            searchInput: 'input[placeholder*="搜索"], input[type="search"]',
            filterButton: 'button:has-text("筛选"), button:has-text("Filter")',
            categoryFilter: '[data-testid="category-filter"]',
            distanceFilter: '[data-testid="distance-filter"]',
            locationButton: 'button[aria-label*="location"], .location-btn, [data-testid="location"]',
            currentLocationMarker: '.current-location, .user-location',
            discoveryNotification: '.discovery-notification, [data-testid="discovery"]',
            rewardAmount: '.reward-amount, [data-testid="reward-amount"]',
            claimRewardButton: 'button:has-text("领取"), button:has-text("Claim")',
            geofenceRadius: '.geofence, .discovery-zone',
            loadingSpinner: '.loading, .spinner, [data-testid="loading"]',
            errorMessage: '.error, [role="alert"]',
            locationPermissionError: '.location-error, [data-testid="location-error"]',
        };
    }
    async navigateToMap() {
        await this.navigateTo('/map');
        await this.waitForPageLoad();
        await this.waitForMapLoad();
    }
    async waitForMapLoad() {
        await this.waitForElement(this.selectors.mapContainer);
        await this.page.waitForTimeout(2000);
        await this.page.locator(this.selectors.loadingSpinner).waitFor({
            state: 'hidden',
            timeout: 10000
        }).catch(() => {
        });
    }
    async createAnnotation(annotationData) {
        await this.clickMapLocation(annotationData.latitude, annotationData.longitude);
        await this.clickElement(this.selectors.createAnnotationButton);
        await this.waitForElement(this.selectors.annotationForm);
        await this.fillElement(this.selectors.titleInput, annotationData.title);
        await this.fillElement(this.selectors.descriptionInput, annotationData.description);
        await this.selectOption(this.selectors.categorySelect, annotationData.category);
        const intensitySlider = this.page.locator(this.selectors.smellIntensity);
        await intensitySlider.fill(annotationData.intensity.toString());
        await this.fillElement(this.selectors.rewardAmount, annotationData.rewardAmount.toString());
        if (annotationData.mediaFile) {
            await this.uploadFile(this.selectors.mediaUpload, annotationData.mediaFile);
        }
        const createResponsePromise = this.page.waitForResponse(response => response.url().includes('/api/annotations') && response.status() === 201);
        await this.clickElement(this.selectors.submitButton);
        await createResponsePromise;
        await this.waitForPageLoad();
    }
    async clickMapLocation(latitude, longitude) {
        const mapContainer = await this.waitForElement(this.selectors.mapContainer);
        const mapBounds = await mapContainer.boundingBox();
        if (!mapBounds)
            throw new Error('无法获取地图边界');
        const x = mapBounds.x + mapBounds.width / 2;
        const y = mapBounds.y + mapBounds.height / 2;
        await this.page.mouse.click(x, y);
        await this.page.waitForTimeout(500);
    }
    async searchAnnotations(query) {
        await this.fillElement(this.selectors.searchInput, query);
        await this.page.keyboard.press('Enter');
        await this.waitForPageLoad();
    }
    async filterAnnotations(filters) {
        await this.clickElement(this.selectors.filterButton);
        if (filters.category) {
            await this.selectOption(this.selectors.categoryFilter, filters.category);
        }
        if (filters.maxDistance) {
            await this.fillElement(this.selectors.distanceFilter, filters.maxDistance.toString());
        }
        await this.page.keyboard.press('Enter');
        await this.waitForPageLoad();
    }
    async clickAnnotationMarker(index = 0) {
        const markers = this.page.locator(this.selectors.annotationMarker);
        await markers.nth(index).click();
        await this.waitForElement(this.selectors.annotationPopup);
    }
    async verifyAnnotationDetails(expectedData) {
        const popup = this.page.locator(this.selectors.annotationPopup);
        await (0, test_1.expect)(popup).toBeVisible();
        const titleElement = popup.locator(this.selectors.annotationTitle);
        await (0, test_1.expect)(titleElement).toContainText(expectedData.title);
        const descriptionElement = popup.locator(this.selectors.annotationDescription);
        await (0, test_1.expect)(descriptionElement).toContainText(expectedData.description);
    }
    async likeAnnotation() {
        await this.clickElement(this.selectors.likeButton);
        await this.waitForAPI('/api/annotations/like');
        const likeButton = this.page.locator(this.selectors.likeButton);
        await (0, test_1.expect)(likeButton).toHaveClass(/liked|active/);
    }
    async getCurrentLocation() {
        await this.clickElement(this.selectors.locationButton);
        await this.page.waitForTimeout(2000);
        await (0, test_1.expect)(this.page.locator(this.selectors.currentLocationMarker)).toBeVisible();
    }
    async enterGeofence(latitude, longitude) {
        await this.page.context().setGeolocation({ latitude, longitude });
        await this.page.evaluate(() => {
            window.dispatchEvent(new Event('locationupdate'));
        });
        await this.waitForElement(this.selectors.discoveryNotification);
    }
    async verifyRewardDiscovery(expectedAmount) {
        const notification = this.page.locator(this.selectors.discoveryNotification);
        await (0, test_1.expect)(notification).toBeVisible();
        const rewardAmountElement = notification.locator(this.selectors.rewardAmount);
        await (0, test_1.expect)(rewardAmountElement).toContainText(expectedAmount.toString());
    }
    async claimReward() {
        await this.clickElement(this.selectors.claimRewardButton);
        await this.waitForAPI('/api/rewards/claim');
        await this.verifyToastMessage('奖励已领取');
    }
    async verifyAnnotationCount(expectedCount) {
        const markers = this.page.locator(this.selectors.annotationMarker);
        await (0, test_1.expect)(markers).toHaveCount(expectedCount);
    }
    async verifyLocationPermissionError() {
        const errorElement = this.page.locator(this.selectors.locationPermissionError);
        await (0, test_1.expect)(errorElement).toBeVisible();
        await (0, test_1.expect)(errorElement).toContainText(/位置|permission|location/i);
    }
    async waitForMapInteraction() {
        await this.waitForElement(this.selectors.mapContainer);
        await this.page.waitForFunction(() => {
            const map = window.map;
            return map && map._loaded;
        }, { timeout: 15000 }).catch(() => {
            return this.page.waitForTimeout(3000);
        });
    }
}
exports.MapPage = MapPage;
//# sourceMappingURL=map-page.js.map