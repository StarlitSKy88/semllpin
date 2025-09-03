"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const LBSSettings = ({ className = '', onSettingsChange }) => {
    const [settings, setSettings] = (0, react_1.useState)({
        locationTracking: {
            enabled: true,
            accuracy: 'high',
            updateInterval: 30,
            backgroundTracking: false,
            batteryOptimization: true
        },
        geofencing: {
            enabled: true,
            detectionRadius: 50,
            minStayDuration: 60,
            maxDailyRewards: 10,
            autoCheckin: true
        },
        notifications: {
            enabled: true,
            rewardNotifications: true,
            geofenceEntry: true,
            geofenceExit: false,
            dailySummary: true,
            sound: true,
            vibration: true
        },
        privacy: {
            shareLocation: false,
            anonymousMode: false,
            dataRetention: 90,
            allowAnalytics: true
        },
        performance: {
            cacheSize: 50,
            offlineMode: true,
            dataCompression: true,
            lowDataMode: false
        }
    });
    const [loading, setLoading] = (0, react_1.useState)(true);
    const [saving, setSaving] = (0, react_1.useState)(false);
    const [error, setError] = (0, react_1.useState)(null);
    const [hasChanges, setHasChanges] = (0, react_1.useState)(false);
    const [activeTab, setActiveTab] = (0, react_1.useState)('location');
    const loadSettings = async () => {
        try {
            setLoading(true);
            setError(null);
            const savedSettings = localStorage.getItem('lbs_settings');
            if (savedSettings) {
                const parsed = JSON.parse(savedSettings);
                setSettings(prev => ({ ...prev, ...parsed }));
            }
        }
        catch (err) {
            console.error('加载设置失败:', err);
            setError('加载设置失败');
        }
        finally {
            setLoading(false);
        }
    };
    const saveSettings = async () => {
        try {
            setSaving(true);
            setError(null);
            localStorage.setItem('lbs_settings', JSON.stringify(settings));
            onSettingsChange?.(settings);
            setHasChanges(false);
        }
        catch (err) {
            console.error('保存设置失败:', err);
            setError('保存设置失败');
        }
        finally {
            setSaving(false);
        }
    };
    const resetSettings = () => {
        const defaultSettings = {
            locationTracking: {
                enabled: true,
                accuracy: 'high',
                updateInterval: 30,
                backgroundTracking: false,
                batteryOptimization: true
            },
            geofencing: {
                enabled: true,
                detectionRadius: 50,
                minStayDuration: 60,
                maxDailyRewards: 10,
                autoCheckin: true
            },
            notifications: {
                enabled: true,
                rewardNotifications: true,
                geofenceEntry: true,
                geofenceExit: false,
                dailySummary: true,
                sound: true,
                vibration: true
            },
            privacy: {
                shareLocation: false,
                anonymousMode: false,
                dataRetention: 90,
                allowAnalytics: true
            },
            performance: {
                cacheSize: 50,
                offlineMode: true,
                dataCompression: true,
                lowDataMode: false
            }
        };
        setSettings(defaultSettings);
        setHasChanges(true);
    };
    const updateSetting = (category, key, value) => {
        setSettings(prev => ({
            ...prev,
            [category]: {
                ...prev[category],
                [key]: value
            }
        }));
        setHasChanges(true);
    };
    const getAccuracyDescription = (accuracy) => {
        const descriptions = {
            high: '高精度 (GPS + 网络，耗电较多)',
            medium: '中等精度 (网络定位，平衡模式)',
            low: '低精度 (基站定位，省电模式)'
        };
        return descriptions[accuracy] || '';
    };
    const getIntervalDescription = (interval) => {
        if (interval < 60)
            return `${interval}秒 (高频率，耗电较多)`;
        if (interval < 300)
            return `${interval}秒 (中等频率)`;
        return `${interval}秒 (低频率，省电)`;
    };
    (0, react_1.useEffect)(() => {
        loadSettings();
    }, []);
    if (loading) {
        return ((0, jsx_runtime_1.jsx)("div", { className: `bg-white rounded-lg shadow-sm p-6 ${className}`, children: (0, jsx_runtime_1.jsxs)("div", { className: "animate-pulse space-y-4", children: [(0, jsx_runtime_1.jsx)("div", { className: "h-6 bg-gray-200 rounded w-1/3" }), (0, jsx_runtime_1.jsx)("div", { className: "space-y-3", children: [...Array(5)].map((_, i) => ((0, jsx_runtime_1.jsx)("div", { className: "h-12 bg-gray-200 rounded" }, i))) })] }) }));
    }
    const tabs = [
        { id: 'location', label: '位置追踪', icon: lucide_react_1.MapPin },
        { id: 'geofencing', label: '地理围栏', icon: lucide_react_1.Shield },
        { id: 'notifications', label: '通知设置', icon: lucide_react_1.Bell },
        { id: 'privacy', label: '隐私设置', icon: lucide_react_1.Shield },
        { id: 'performance', label: '性能设置', icon: lucide_react_1.Battery }
    ];
    return ((0, jsx_runtime_1.jsxs)("div", { className: `bg-white rounded-lg shadow-sm ${className}`, children: [(0, jsx_runtime_1.jsxs)("div", { className: "p-6 border-b border-gray-200", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Settings, { className: "h-6 w-6 text-gray-600" }), (0, jsx_runtime_1.jsx)("h2", { className: "text-lg font-semibold text-gray-900", children: "LBS\u8BBE\u7F6E" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex space-x-2", children: [(0, jsx_runtime_1.jsxs)("button", { onClick: resetSettings, className: "flex items-center space-x-1 px-3 py-2 text-sm text-gray-600 hover:text-gray-900 border border-gray-300 rounded-md hover:bg-gray-50", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.RotateCcw, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u91CD\u7F6E" })] }), (0, jsx_runtime_1.jsxs)("button", { onClick: saveSettings, disabled: !hasChanges || saving, className: "flex items-center space-x-1 px-4 py-2 text-sm text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Save, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: saving ? '保存中...' : '保存设置' })] })] })] }), error && ((0, jsx_runtime_1.jsx)("div", { className: "mt-4 p-3 bg-red-50 border border-red-200 rounded-md", children: (0, jsx_runtime_1.jsx)("div", { className: "text-red-700 text-sm", children: error }) })), hasChanges && ((0, jsx_runtime_1.jsx)("div", { className: "mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md", children: (0, jsx_runtime_1.jsx)("div", { className: "text-yellow-700 text-sm", children: "\u8BBE\u7F6E\u5DF2\u4FEE\u6539\uFF0C\u8BF7\u4FDD\u5B58\u66F4\u6539" }) }))] }), (0, jsx_runtime_1.jsx)("div", { className: "border-b border-gray-200", children: (0, jsx_runtime_1.jsx)("nav", { className: "flex space-x-8 px-6", children: tabs.map((tab) => {
                        const Icon = tab.icon;
                        return ((0, jsx_runtime_1.jsxs)("button", { onClick: () => setActiveTab(tab.id), className: `flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm ${activeTab === tab.id
                                ? 'border-blue-500 text-blue-600'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}`, children: [(0, jsx_runtime_1.jsx)(Icon, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: tab.label })] }, tab.id));
                    }) }) }), (0, jsx_runtime_1.jsxs)("div", { className: "p-6", children: [activeTab === 'location' && ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { className: "text-lg font-medium text-gray-900", children: "\u4F4D\u7F6E\u8FFD\u8E2A" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600", children: "\u914D\u7F6E\u4F4D\u7F6E\u83B7\u53D6\u548C\u8FFD\u8E2A\u76F8\u5173\u8BBE\u7F6E" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "relative inline-flex items-center cursor-pointer", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.locationTracking.enabled, onChange: (e) => updateSetting('locationTracking', 'enabled', e.target.checked), className: "sr-only peer" }), (0, jsx_runtime_1.jsx)("div", { className: "w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600" })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: "\u5B9A\u4F4D\u7CBE\u5EA6" }), (0, jsx_runtime_1.jsxs)("select", { value: settings.locationTracking.accuracy, onChange: (e) => updateSetting('locationTracking', 'accuracy', e.target.value), disabled: !settings.locationTracking.enabled, className: "w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100", children: [(0, jsx_runtime_1.jsx)("option", { value: "high", children: "\u9AD8\u7CBE\u5EA6" }), (0, jsx_runtime_1.jsx)("option", { value: "medium", children: "\u4E2D\u7B49\u7CBE\u5EA6" }), (0, jsx_runtime_1.jsx)("option", { value: "low", children: "\u4F4E\u7CBE\u5EA6" })] }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-500 mt-1", children: getAccuracyDescription(settings.locationTracking.accuracy) })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: ["\u66F4\u65B0\u95F4\u9694: ", settings.locationTracking.updateInterval, "\u79D2"] }), (0, jsx_runtime_1.jsx)("input", { type: "range", min: "10", max: "300", step: "10", value: settings.locationTracking.updateInterval, onChange: (e) => updateSetting('locationTracking', 'updateInterval', parseInt(e.target.value)), disabled: !settings.locationTracking.enabled, className: "w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:cursor-not-allowed" }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-500 mt-1", children: getIntervalDescription(settings.locationTracking.updateInterval) })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-3", children: [(0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.locationTracking.backgroundTracking, onChange: (e) => updateSetting('locationTracking', 'backgroundTracking', e.target.checked), disabled: !settings.locationTracking.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u540E\u53F0\u4F4D\u7F6E\u8FFD\u8E2A" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.locationTracking.batteryOptimization, onChange: (e) => updateSetting('locationTracking', 'batteryOptimization', e.target.checked), disabled: !settings.locationTracking.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u7535\u6C60\u4F18\u5316\u6A21\u5F0F" })] })] })] })] })), activeTab === 'geofencing' && ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { className: "text-lg font-medium text-gray-900", children: "\u5730\u7406\u56F4\u680F" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600", children: "\u914D\u7F6E\u5730\u7406\u56F4\u680F\u68C0\u6D4B\u548C\u5956\u52B1\u76F8\u5173\u8BBE\u7F6E" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "relative inline-flex items-center cursor-pointer", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.geofencing.enabled, onChange: (e) => updateSetting('geofencing', 'enabled', e.target.checked), className: "sr-only peer" }), (0, jsx_runtime_1.jsx)("div", { className: "w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600" })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: ["\u68C0\u6D4B\u534A\u5F84: ", settings.geofencing.detectionRadius, "\u7C73"] }), (0, jsx_runtime_1.jsx)("input", { type: "range", min: "10", max: "200", step: "10", value: settings.geofencing.detectionRadius, onChange: (e) => updateSetting('geofencing', 'detectionRadius', parseInt(e.target.value)), disabled: !settings.geofencing.enabled, className: "w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:cursor-not-allowed" })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: ["\u6700\u5C0F\u505C\u7559\u65F6\u95F4: ", settings.geofencing.minStayDuration, "\u79D2"] }), (0, jsx_runtime_1.jsx)("input", { type: "range", min: "30", max: "300", step: "30", value: settings.geofencing.minStayDuration, onChange: (e) => updateSetting('geofencing', 'minStayDuration', parseInt(e.target.value)), disabled: !settings.geofencing.enabled, className: "w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:cursor-not-allowed" })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: ["\u6BCF\u65E5\u6700\u5927\u5956\u52B1\u6B21\u6570: ", settings.geofencing.maxDailyRewards] }), (0, jsx_runtime_1.jsx)("input", { type: "range", min: "1", max: "50", step: "1", value: settings.geofencing.maxDailyRewards, onChange: (e) => updateSetting('geofencing', 'maxDailyRewards', parseInt(e.target.value)), disabled: !settings.geofencing.enabled, className: "w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer disabled:cursor-not-allowed" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.geofencing.autoCheckin, onChange: (e) => updateSetting('geofencing', 'autoCheckin', e.target.checked), disabled: !settings.geofencing.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u81EA\u52A8\u7B7E\u5230" })] })] })] })), activeTab === 'notifications' && ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { className: "text-lg font-medium text-gray-900", children: "\u901A\u77E5\u8BBE\u7F6E" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600", children: "\u914D\u7F6E\u5404\u79CD\u901A\u77E5\u548C\u63D0\u9192" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "relative inline-flex items-center cursor-pointer", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.notifications.enabled, onChange: (e) => updateSetting('notifications', 'enabled', e.target.checked), className: "sr-only peer" }), (0, jsx_runtime_1.jsx)("div", { className: "w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600" })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-3", children: [(0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.notifications.rewardNotifications, onChange: (e) => updateSetting('notifications', 'rewardNotifications', e.target.checked), disabled: !settings.notifications.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u5956\u52B1\u901A\u77E5" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.notifications.geofenceEntry, onChange: (e) => updateSetting('notifications', 'geofenceEntry', e.target.checked), disabled: !settings.notifications.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u8FDB\u5165\u5730\u7406\u56F4\u680F\u901A\u77E5" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.notifications.geofenceExit, onChange: (e) => updateSetting('notifications', 'geofenceExit', e.target.checked), disabled: !settings.notifications.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u79BB\u5F00\u5730\u7406\u56F4\u680F\u901A\u77E5" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.notifications.dailySummary, onChange: (e) => updateSetting('notifications', 'dailySummary', e.target.checked), disabled: !settings.notifications.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u6BCF\u65E5\u603B\u7ED3" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.notifications.sound, onChange: (e) => updateSetting('notifications', 'sound', e.target.checked), disabled: !settings.notifications.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u58F0\u97F3\u63D0\u9192" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.notifications.vibration, onChange: (e) => updateSetting('notifications', 'vibration', e.target.checked), disabled: !settings.notifications.enabled, className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500 disabled:opacity-50" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u9707\u52A8\u63D0\u9192" })] })] })] })), activeTab === 'privacy' && ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { className: "text-lg font-medium text-gray-900", children: "\u9690\u79C1\u8BBE\u7F6E" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600", children: "\u7BA1\u7406\u60A8\u7684\u9690\u79C1\u548C\u6570\u636E\u5B89\u5168" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.privacy.shareLocation, onChange: (e) => updateSetting('privacy', 'shareLocation', e.target.checked), className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u5141\u8BB8\u5206\u4EAB\u4F4D\u7F6E\u4FE1\u606F" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.privacy.anonymousMode, onChange: (e) => updateSetting('privacy', 'anonymousMode', e.target.checked), className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u533F\u540D\u6A21\u5F0F" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.privacy.allowAnalytics, onChange: (e) => updateSetting('privacy', 'allowAnalytics', e.target.checked), className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u5141\u8BB8\u6570\u636E\u5206\u6790" })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: ["\u6570\u636E\u4FDD\u7559\u671F: ", settings.privacy.dataRetention, "\u5929"] }), (0, jsx_runtime_1.jsx)("input", { type: "range", min: "7", max: "365", step: "7", value: settings.privacy.dataRetention, onChange: (e) => updateSetting('privacy', 'dataRetention', parseInt(e.target.value)), className: "w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer" }), (0, jsx_runtime_1.jsxs)("p", { className: "text-xs text-gray-500 mt-1", children: ["\u4F4D\u7F6E\u6570\u636E\u5C06\u5728", settings.privacy.dataRetention, "\u5929\u540E\u81EA\u52A8\u5220\u9664"] })] })] })] })), activeTab === 'performance' && ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { className: "text-lg font-medium text-gray-900", children: "\u6027\u80FD\u8BBE\u7F6E" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600", children: "\u4F18\u5316\u5E94\u7528\u6027\u80FD\u548C\u6570\u636E\u4F7F\u7528" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: ["\u7F13\u5B58\u5927\u5C0F: ", settings.performance.cacheSize, "MB"] }), (0, jsx_runtime_1.jsx)("input", { type: "range", min: "10", max: "200", step: "10", value: settings.performance.cacheSize, onChange: (e) => updateSetting('performance', 'cacheSize', parseInt(e.target.value)), className: "w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.performance.offlineMode, onChange: (e) => updateSetting('performance', 'offlineMode', e.target.checked), className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u79BB\u7EBF\u6A21\u5F0F" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.performance.dataCompression, onChange: (e) => updateSetting('performance', 'dataCompression', e.target.checked), className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u6570\u636E\u538B\u7F29" })] }), (0, jsx_runtime_1.jsxs)("label", { className: "flex items-center", children: [(0, jsx_runtime_1.jsx)("input", { type: "checkbox", checked: settings.performance.lowDataMode, onChange: (e) => updateSetting('performance', 'lowDataMode', e.target.checked), className: "rounded border-gray-300 text-blue-600 focus:ring-blue-500" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 text-sm text-gray-700", children: "\u4F4E\u6570\u636E\u6A21\u5F0F" })] })] })] }))] })] }));
};
exports.default = LBSSettings;
//# sourceMappingURL=LBSSettings.js.map