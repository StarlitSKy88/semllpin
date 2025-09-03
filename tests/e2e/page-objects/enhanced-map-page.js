"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EnhancedMapPage = void 0;
const test_1 = require("@playwright/test");
const base_page_1 = require("./base-page");
class EnhancedMapPage extends base_page_1.BasePage {
    constructor(page) {
        super(page);
        this.selectors = {
            mapContainer: '#map, .map-container, [data-testid="map"]',
            mapCanvas: '.leaflet-container, .mapboxgl-canvas, canvas',
            mapOverlay: '.map-overlay, .ui-overlay',
            annotationMarkers: '.marker, .annotation-marker, [data-testid*="marker"]',
            userLocationMarker: '.current-location, .user-location, [data-testid="user-location"]',
            selectedMarker: '.marker.selected, .annotation-marker.active',
            markerCluster: '.marker-cluster, .cluster',
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
            annotationDetailModal: '[data-testid="annotation-detail"], .annotation-detail',
            detailTitle: '.annotation-title, [data-testid="annotation-title"]',
            detailDescription: '.annotation-description, [data-testid="annotation-description"]',
            detailAuthor: '.annotation-author, [data-testid="annotation-author"]',
            detailReward: '.reward-amount, [data-testid="reward-amount"]',
            likeButton: 'button:has-text("点赞"), .like-button, [data-testid="like-button"]',
            shareButton: 'button:has-text("分享"), .share-button, [data-testid="share-button"]',
            commentButton: 'button:has-text("评论"), .comment-button, [data-testid="comment-button"]',
            claimRewardButton: 'button:has-text("领取"), .claim-button, [data-testid="claim-reward"]',
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
            zoomInButton: '.leaflet-control-zoom-in, [data-testid="zoom-in"]',
            zoomOutButton: '.leaflet-control-zoom-out, [data-testid="zoom-out"]',
            fullscreenButton: '.fullscreen-button, [data-testid="fullscreen"]',
            layerSwitcher: '.layer-switcher, [data-testid="layer-switcher"]',
            geolocationButton: '.leaflet-control-locate, [data-testid="locate"]',
            mapModeButtons: '.map-mode-buttons, [data-testid="map-modes"]',
            markersMode: 'button:has-text("标记模式"), [data-testid="markers-mode"]',
            heatmapMode: 'button:has-text("热力图"), [data-testid="heatmap-mode"]',
            hybridMode: 'button:has-text("混合模式"), [data-testid="hybrid-mode"]',
            locationTracker: '[data-testid="location-tracker"], .location-tracker',
            geofenceIndicator: '.geofence, .discovery-zone, [data-testid="geofence"]',
            rewardNotification: '.reward-notification, [data-testid="reward-notification"]',
            rewardModal: '[data-testid="reward-modal"], .reward-modal',
            nearbyAnnotations: '[data-testid="nearby-annotations"], .nearby-list',
            paymentModal: '[data-testid="payment-modal"], .payment-modal',
            paymentForm: '[data-testid="payment-form"], .payment-form',
            cardNumberInput: 'input[name="cardNumber"], input[placeholder*="卡号"]',
            expiryInput: 'input[name="expiry"], input[placeholder*="有效期"]',
            cvcInput: 'input[name="cvc"], input[placeholder*="CVC"]',
            cardHolderInput: 'input[name="name"], input[placeholder*="姓名"]',
            paymentSubmitButton: 'button:has-text("支付"), [data-testid="payment-submit"]',
            loadingIndicator: '.loading, .spinner, [data-testid="loading"]',
            errorMessage: '.error, [role="alert"], [data-testid="error"]',
            successMessage: '.success, [data-testid="success"]',
            toastMessage: '.toast, .notification, [data-testid="toast"]',
            topNavigation: '.top-navigation, [data-testid="top-nav"]',
            userMenu: '.user-menu, [data-testid="user-menu"]',
            walletButton: 'button:has-text("钱包"), [data-testid="wallet-button"]',
            profileButton: 'button:has-text("个人资料"), [data-testid="profile-button"]',
        };
    }
    async waitForMapFullyLoaded() {
        await this.waitForElement(this.selectors.mapContainer);
        await this.page.waitForFunction(() => {
            const mapElement = document.querySelector('#map, .map-container, [data-testid="map"]');
            if (!mapElement)
                return false;
            const map = window.map || window.__map__;
            if (map && map._loaded)
                return true;
            if (window.L && window.L.DomUtil) {
                const tiles = document.querySelectorAll('.leaflet-tile');
                return tiles.length > 0;
            }
            return false;
        }, { timeout: 15000 });
        await this.page.waitForTimeout(2000);
    }
    async clickMapLocationSmart(lat, lng) {
        const mapContainer = await this.waitForElement(this.selectors.mapContainer);
        const mapBounds = await mapContainer.boundingBox();
        if (!mapBounds) {
            throw new Error('无法获取地图边界');
        }
        const centerLat = await this.page.evaluate(() => {
            const map = window.map;
            return map ? map.getCenter().lat : 39.9042;
        });
        const centerLng = await this.page.evaluate(() => {
            const map = window.map;
            return map ? map.getCenter().lng : 116.4074;
        });
        const zoom = await this.page.evaluate(() => {
            const map = window.map;
            return map ? map.getZoom() : 13;
        });
        const scale = Math.pow(2, zoom - 10);
        const relativeX = (lng - centerLng) * scale * 1000;
        const relativeY = (centerLat - lat) * scale * 1000;
        const pixelX = mapBounds.x + mapBounds.width / 2 + relativeX;
        const pixelY = mapBounds.y + mapBounds.height / 2 + relativeY;
        const clampedX = Math.max(mapBounds.x, Math.min(mapBounds.x + mapBounds.width, pixelX));
        const clampedY = Math.max(mapBounds.y, Math.min(mapBounds.y + mapBounds.height, pixelY));
        await this.page.mouse.click(clampedX, clampedY);
        await this.page.waitForTimeout(500);
    }
    async createDetailedAnnotation(annotationData) {
        await this.clickMapLocationSmart(annotationData.latitude, annotationData.longitude);
        await this.waitForElement(this.selectors.createAnnotationModal);
        await this.fillElement(this.selectors.titleInput, annotationData.title);
        await this.fillElement(this.selectors.descriptionTextarea, annotationData.description);
        if (await this.page.locator(this.selectors.categorySelect).isVisible()) {
            await this.selectOption(this.selectors.categorySelect, annotationData.category);
        }
        const intensitySlider = this.page.locator(this.selectors.intensitySlider);
        if (await intensitySlider.isVisible()) {
            await intensitySlider.click();
            const sliderBounds = await intensitySlider.boundingBox();
            if (sliderBounds) {
                const x = sliderBounds.x + (sliderBounds.width * annotationData.intensity / 5);
                await this.page.mouse.click(x, sliderBounds.y + sliderBounds.height / 2);
            }
        }
        if (await this.page.locator(this.selectors.rewardAmountInput).isVisible()) {
            await this.fillElement(this.selectors.rewardAmountInput, annotationData.rewardAmount.toString());
        }
        if (annotationData.images && annotationData.images.length > 0) {
            for (const imagePath of annotationData.images) {
                await this.uploadFile(this.selectors.imageUpload, imagePath);
                await this.page.waitForTimeout(1000);
            }
        }
        const submitPromise = this.page.waitForResponse(response => response.url().includes('/api/annotations') && response.status() === 201);
        await this.clickElement(this.selectors.submitButton);
        try {
            await submitPromise;
        }
        catch {
            await this.page.waitForTimeout(3000);
        }
    }
    async performAdvancedSearch(searchCriteria) {
        await this.clickElement(this.selectors.filterButton);
        await this.waitForElement(this.selectors.advancedFilterModal);
        if (searchCriteria.keyword) {
            await this.fillElement(this.selectors.searchInput, searchCriteria.keyword);
        }
        if (searchCriteria.category) {
            await this.selectOption(this.selectors.categoryFilter, searchCriteria.category);
        }
        if (searchCriteria.minReward !== undefined || searchCriteria.maxReward !== undefined) {
            const rewardFilter = this.page.locator(this.selectors.rewardRangeFilter);
            if (await rewardFilter.isVisible()) {
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
        await this.clickElement(this.selectors.applyFilterButton);
        await this.waitForPageLoad();
    }
    async simulateGeofenceEntry(lat, lng, radius = 100) {
        await this.page.context().setGeolocation({ latitude: lat + 0.001, longitude: lng + 0.001 });
        await this.page.waitForTimeout(1000);
        await this.page.context().setGeolocation({ latitude: lat, longitude: lng });
        await this.page.evaluate(() => {
            window.dispatchEvent(new CustomEvent('locationupdate', {
                detail: { latitude: lat, longitude: lng }
            }));
            if (navigator.geolocation) {
                const event = new Event('geolocationchange');
                window.dispatchEvent(event);
            }
        });
        await this.page.waitForTimeout(2000);
    }
    async verifyAndClaimReward(expectedAmount) {
        await this.waitForElement(this.selectors.rewardNotification, { timeout: 10000 });
        const rewardElement = this.page.locator(this.selectors.detailReward);
        await (0, test_1.expect)(rewardElement).toContainText(expectedAmount.toString());
        const claimButton = this.page.locator(this.selectors.claimRewardButton);
        if (await claimButton.isVisible()) {
            const claimPromise = this.page.waitForResponse(response => response.url().includes('/api/rewards/claim'));
            await claimButton.click();
            try {
                await claimPromise;
            }
            catch {
                await this.page.waitForTimeout(3000);
            }
        }
        await this.verifyToastMessage('奖励已领取|领取成功');
    }
    async simulatePaymentFlow(paymentData) {
        await this.waitForElement(this.selectors.paymentModal);
        await this.fillElement(this.selectors.cardNumberInput, paymentData.cardNumber);
        await this.fillElement(this.selectors.expiryInput, paymentData.expiry);
        await this.fillElement(this.selectors.cvcInput, paymentData.cvc);
        await this.fillElement(this.selectors.cardHolderInput, paymentData.name);
        const paymentPromise = this.page.waitForResponse(response => response.url().includes('/api/payments') || response.url().includes('stripe.com'));
        await this.clickElement(this.selectors.paymentSubmitButton);
        try {
            await paymentPromise;
        }
        catch {
            await this.page.waitForTimeout(3000);
        }
    }
    async verifyMarkerClustering(expectedClusterCount) {
        const clusters = this.page.locator(this.selectors.markerCluster);
        await (0, test_1.expect)(clusters).toHaveCount(expectedClusterCount);
        if (expectedClusterCount > 0) {
            await clusters.first().click();
            await this.page.waitForTimeout(1000);
            const individualMarkers = this.page.locator(this.selectors.annotationMarkers);
            await (0, test_1.expect)(individualMarkers.first()).toBeVisible();
        }
    }
    async testMapPanAndZoom() {
        const mapContainer = await this.waitForElement(this.selectors.mapContainer);
        const bounds = await mapContainer.boundingBox();
        if (!bounds)
            return;
        const startX = bounds.x + bounds.width / 2;
        const startY = bounds.y + bounds.height / 2;
        const endX = startX + 100;
        const endY = startY + 100;
        await this.page.mouse.move(startX, startY);
        await this.page.mouse.down();
        await this.page.mouse.move(endX, endY, { steps: 10 });
        await this.page.mouse.up();
        await this.page.waitForTimeout(1000);
        await this.page.mouse.move(startX, startY);
        await this.page.mouse.wheel(0, -100);
        await this.page.waitForTimeout(1000);
        await this.page.mouse.wheel(0, 100);
        await this.page.waitForTimeout(1000);
    }
    async verifyResponsiveMapBehavior(viewportWidth) {
        if (viewportWidth <= 768) {
            await (0, test_1.expect)(this.page.locator('.mobile-controls')).toBeVisible();
            await (0, test_1.expect)(this.page.locator('.desktop-only')).toBeHidden();
        }
        else {
            await (0, test_1.expect)(this.page.locator('.desktop-controls')).toBeVisible();
            await (0, test_1.expect)(this.page.locator('.mobile-only')).toBeHidden();
        }
    }
    async getMapPerformanceMetrics() {
        return await this.page.evaluate(() => {
            const performance = window.performance;
            const entries = performance.getEntriesByType('navigation')[0];
            return {
                domContentLoaded: entries.domContentLoadedEventEnd - entries.domContentLoadedEventStart,
                loadComplete: entries.loadEventEnd - entries.loadEventStart,
                firstPaint: performance.getEntriesByName('first-paint')[0]?.startTime || 0,
                firstContentfulPaint: performance.getEntriesByName('first-contentful-paint')[0]?.startTime || 0,
                mapTileLoadTime: window.__mapTileLoadTime__ || 0,
                annotationRenderTime: window.__annotationRenderTime__ || 0
            };
        });
    }
    async simulateNetworkChange(condition) {
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
                    }, 2000);
                });
                break;
        }
        await this.page.waitForTimeout(1000);
    }
    async verifyErrorRecovery() {
        const retryButton = this.page.locator('button:has-text("重试"), .retry-button');
        if (await retryButton.isVisible()) {
            await retryButton.click();
            await this.page.waitForTimeout(2000);
        }
        const errorMessage = this.page.locator(this.selectors.errorMessage);
        await (0, test_1.expect)(errorMessage).toBeHidden();
    }
}
exports.EnhancedMapPage = EnhancedMapPage;
//# sourceMappingURL=enhanced-map-page.js.map