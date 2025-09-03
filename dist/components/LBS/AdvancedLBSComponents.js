"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const tabs_1 = require("../ui/tabs");
const card_1 = require("../ui/card");
const button_1 = require("../ui/button");
const badge_1 = require("../ui/badge");
const lucide_react_1 = require("lucide-react");
const RadarScanner_1 = __importDefault(require("./RadarScanner"));
const DistanceIndicator_1 = __importDefault(require("./DistanceIndicator"));
const BatteryOptimizer_1 = __importDefault(require("./BatteryOptimizer"));
const AdvancedLBSComponents = ({ userLocation, geofenceTargets, onTargetDetected, onSettingsChange, className = '' }) => {
    const [activeTab, setActiveTab] = (0, react_1.useState)('radar');
    const [radarTargets, setRadarTargets] = (0, react_1.useState)([]);
    const [selectedTarget, setSelectedTarget] = (0, react_1.useState)(null);
    const [currentPowerProfile, setCurrentPowerProfile] = (0, react_1.useState)(null);
    const [isScanning, setIsScanning] = (0, react_1.useState)(false);
    const [scanRange, setScanRange] = (0, react_1.useState)(500);
    const [scanSpeed, setScanSpeed] = (0, react_1.useState)(2000);
    const [optimizationStats, setOptimizationStats] = (0, react_1.useState)({
        batteryLevel: 100,
        estimatedRuntime: 0,
        powerSavings: 0
    });
    const convertToRadarTargets = (0, react_1.useCallback)((targets, userLoc) => {
        return targets.map(target => {
            const distance = calculateDistance(userLoc, target.location);
            const bearing = calculateBearing(userLoc, target.location);
            return {
                id: target.id,
                name: target.name,
                distance,
                bearing,
                type: target.type,
                strength: Math.max(0.1, Math.min(1, (scanRange - distance) / scanRange)),
                data: target
            };
        }).filter(target => target.distance <= scanRange);
    }, [scanRange]);
    const calculateDistance = (loc1, loc2) => {
        const R = 6371000;
        const lat1Rad = (loc1.latitude * Math.PI) / 180;
        const lat2Rad = (loc2.latitude * Math.PI) / 180;
        const deltaLatRad = ((loc2.latitude - loc1.latitude) * Math.PI) / 180;
        const deltaLonRad = ((loc2.longitude - loc1.longitude) * Math.PI) / 180;
        const a = Math.sin(deltaLatRad / 2) * Math.sin(deltaLatRad / 2) +
            Math.cos(lat1Rad) * Math.cos(lat2Rad) *
                Math.sin(deltaLonRad / 2) * Math.sin(deltaLonRad / 2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    };
    const calculateBearing = (loc1, loc2) => {
        const lat1Rad = (loc1.latitude * Math.PI) / 180;
        const lat2Rad = (loc2.latitude * Math.PI) / 180;
        const deltaLonRad = ((loc2.longitude - loc1.longitude) * Math.PI) / 180;
        const y = Math.sin(deltaLonRad) * Math.cos(lat2Rad);
        const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) -
            Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(deltaLonRad);
        const bearingRad = Math.atan2(y, x);
        return (bearingRad * 180 / Math.PI + 360) % 360;
    };
    const handleTargetDetected = (0, react_1.useCallback)((target) => {
        console.log('Target detected:', target);
        onTargetDetected?.(target);
        if (target.type === 'geofence' && target.data) {
            setSelectedTarget(target.data);
        }
    }, [onTargetDetected]);
    const handleDistanceTargetSelect = (0, react_1.useCallback)((target) => {
        setSelectedTarget(target);
        setActiveTab('radar');
    }, []);
    const handlePowerProfileChange = (0, react_1.useCallback)((profile) => {
        setCurrentPowerProfile(profile);
        setScanSpeed(profile.settings.radarScanInterval);
        const rangeMultiplier = {
            'high': 1.0,
            'medium': 0.8,
            'low': 0.6
        };
        setScanRange(500 * rangeMultiplier[profile.settings.accuracyLevel]);
        onSettingsChange?.({
            powerProfile: profile,
            scanRange: scanRange * rangeMultiplier[profile.settings.accuracyLevel],
            scanSpeed: profile.settings.radarScanInterval
        });
    }, [scanRange, onSettingsChange]);
    const handleOptimizationApply = (0, react_1.useCallback)((settings) => {
        setScanSpeed(settings.radarScanInterval);
        setOptimizationStats(prev => ({
            ...prev,
            powerSavings: prev.powerSavings + 5,
            estimatedRuntime: settings.locationUpdateInterval > 30000 ? 8 : 4
        }));
    }, []);
    const toggleScanning = () => {
        setIsScanning(!isScanning);
    };
    (0, react_1.useEffect)(() => {
        const targets = convertToRadarTargets(geofenceTargets, userLocation);
        setRadarTargets(targets);
    }, [geofenceTargets, userLocation, convertToRadarTargets]);
    (0, react_1.useEffect)(() => {
        const interval = setInterval(() => {
            setOptimizationStats(prev => ({
                ...prev,
                batteryLevel: Math.max(0, prev.batteryLevel - (isScanning ? 0.1 : 0.05))
            }));
        }, 10000);
        return () => clearInterval(interval);
    }, [isScanning]);
    return ((0, jsx_runtime_1.jsxs)("div", { className: `w-full max-w-6xl mx-auto ${className}`, children: [(0, jsx_runtime_1.jsxs)(card_1.Card, { className: "mb-6", children: [(0, jsx_runtime_1.jsxs)(card_1.CardHeader, { children: [(0, jsx_runtime_1.jsxs)(card_1.CardTitle, { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Target, { className: "h-5 w-5 text-blue-500" }), (0, jsx_runtime_1.jsx)("span", { children: "\u9AD8\u7EA7LBS\u63A7\u5236\u4E2D\u5FC3" })] }), (0, jsx_runtime_1.jsx)(card_1.CardDescription, { children: "\u96C6\u6210\u96F7\u8FBE\u626B\u63CF\u3001\u8DDD\u79BB\u5BFC\u822A\u548C\u7535\u6C60\u4F18\u5316\u529F\u80FD" })] }), (0, jsx_runtime_1.jsxs)(card_1.CardContent, { children: [(0, jsx_runtime_1.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-4 gap-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: `w-3 h-3 rounded-full ${isScanning ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}` }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("div", { className: "text-sm font-medium", children: isScanning ? '扫描中' : '已停止' }), (0, jsx_runtime_1.jsxs)("div", { className: "text-xs text-gray-600", children: ["\u8303\u56F4: ", scanRange, "m"] })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.MapPin, { className: "h-4 w-4 text-blue-500" }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("div", { className: "text-sm font-medium", children: [radarTargets.length, " \u4E2A\u76EE\u6807"] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-xs text-gray-600", children: [geofenceTargets.filter(t => t.isActive).length, " \u4E2A\u6D3B\u8DC3"] })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Battery, { className: "h-4 w-4 text-green-500" }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("div", { className: "text-sm font-medium", children: [Math.round(optimizationStats.batteryLevel), "%"] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-xs text-gray-600", children: ["\u9884\u4F30 ", optimizationStats.estimatedRuntime, "h"] })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Settings, { className: "h-4 w-4 text-purple-500" }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("div", { className: "text-sm font-medium", children: currentPowerProfile?.name || '默认' }), (0, jsx_runtime_1.jsxs)("div", { className: "text-xs text-gray-600", children: ["\u8282\u7535 ", optimizationStats.powerSavings, "%"] })] })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "mt-4 flex items-center space-x-2", children: [(0, jsx_runtime_1.jsxs)(button_1.Button, { onClick: toggleScanning, variant: isScanning ? 'destructive' : 'default', size: "sm", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Radar, { className: "h-4 w-4 mr-2" }), isScanning ? '停止扫描' : '开始扫描'] }), selectedTarget && ((0, jsx_runtime_1.jsxs)(badge_1.Badge, { variant: "secondary", className: "flex items-center space-x-1", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Navigation, { className: "h-3 w-3" }), (0, jsx_runtime_1.jsxs)("span", { children: ["\u5BFC\u822A\u81F3: ", selectedTarget.name] })] }))] })] })] }), (0, jsx_runtime_1.jsxs)(tabs_1.Tabs, { value: activeTab, onValueChange: setActiveTab, className: "w-full", children: [(0, jsx_runtime_1.jsxs)(tabs_1.TabsList, { className: "grid w-full grid-cols-3", children: [(0, jsx_runtime_1.jsxs)(tabs_1.TabsTrigger, { value: "radar", className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Radar, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u96F7\u8FBE\u626B\u63CF" })] }), (0, jsx_runtime_1.jsxs)(tabs_1.TabsTrigger, { value: "navigation", className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Navigation, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u8DDD\u79BB\u5BFC\u822A" })] }), (0, jsx_runtime_1.jsxs)(tabs_1.TabsTrigger, { value: "battery", className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Battery, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u7535\u6C60\u4F18\u5316" })] })] }), (0, jsx_runtime_1.jsx)(tabs_1.TabsContent, { value: "radar", className: "mt-6", children: (0, jsx_runtime_1.jsxs)(card_1.Card, { children: [(0, jsx_runtime_1.jsxs)(card_1.CardHeader, { children: [(0, jsx_runtime_1.jsxs)(card_1.CardTitle, { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Radar, { className: "h-5 w-5 text-green-500" }), (0, jsx_runtime_1.jsx)("span", { children: "\u96F7\u8FBE\u626B\u63CF\u5668" })] }), (0, jsx_runtime_1.jsx)(card_1.CardDescription, { children: "\u5B9E\u65F6\u626B\u63CF\u5468\u56F4\u7684\u5730\u7406\u56F4\u680F\u548C\u5174\u8DA3\u70B9" })] }), (0, jsx_runtime_1.jsxs)(card_1.CardContent, { children: [(0, jsx_runtime_1.jsx)(RadarScanner_1.default, { targets: radarTargets, isScanning: isScanning, maxRange: scanRange, scanSpeed: scanSpeed, onTargetDetected: handleTargetDetected, showGrid: true, className: "w-full h-96" }), (0, jsx_runtime_1.jsxs)("div", { className: "mt-4 grid grid-cols-2 gap-4", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: ["\u626B\u63CF\u8303\u56F4: ", scanRange, "m"] }), (0, jsx_runtime_1.jsx)("input", { type: "range", min: "100", max: "1000", step: "50", value: scanRange, onChange: (e) => setScanRange(Number(e.target.value)), className: "w-full" })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsxs)("label", { className: "block text-sm font-medium text-gray-700 mb-2", children: ["\u626B\u63CF\u901F\u5EA6: ", scanSpeed, "ms"] }), (0, jsx_runtime_1.jsx)("input", { type: "range", min: "1000", max: "5000", step: "500", value: scanSpeed, onChange: (e) => setScanSpeed(Number(e.target.value)), className: "w-full" })] })] })] })] }) }), (0, jsx_runtime_1.jsx)(tabs_1.TabsContent, { value: "navigation", className: "mt-6", children: (0, jsx_runtime_1.jsxs)(card_1.Card, { children: [(0, jsx_runtime_1.jsxs)(card_1.CardHeader, { children: [(0, jsx_runtime_1.jsxs)(card_1.CardTitle, { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Navigation, { className: "h-5 w-5 text-blue-500" }), (0, jsx_runtime_1.jsx)("span", { children: "\u8DDD\u79BB\u5BFC\u822A" })] }), (0, jsx_runtime_1.jsx)(card_1.CardDescription, { children: "\u663E\u793A\u5230\u76EE\u6807\u5730\u70B9\u7684\u8DDD\u79BB\u3001\u65B9\u5411\u548C\u5BFC\u822A\u4FE1\u606F" })] }), (0, jsx_runtime_1.jsx)(card_1.CardContent, { children: (0, jsx_runtime_1.jsx)(DistanceIndicator_1.default, { userLocation: userLocation, targets: geofenceTargets, selectedTargetId: selectedTarget?.id || '', onTargetSelect: handleDistanceTargetSelect, showNavigation: true, maxDisplayTargets: 5, sortBy: "distance", className: "h-64" }) })] }) }), (0, jsx_runtime_1.jsx)(tabs_1.TabsContent, { value: "battery", className: "mt-6", children: (0, jsx_runtime_1.jsxs)(card_1.Card, { children: [(0, jsx_runtime_1.jsxs)(card_1.CardHeader, { children: [(0, jsx_runtime_1.jsxs)(card_1.CardTitle, { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Battery, { className: "h-5 w-5 text-green-500" }), (0, jsx_runtime_1.jsx)("span", { children: "\u7535\u6C60\u4F18\u5316" })] }), (0, jsx_runtime_1.jsx)(card_1.CardDescription, { children: "\u76D1\u63A7\u7535\u6C60\u72B6\u6001\u5E76\u4F18\u5316LBS\u529F\u80FD\u7684\u7535\u91CF\u6D88\u8017" })] }), (0, jsx_runtime_1.jsxs)(card_1.CardContent, { children: [(0, jsx_runtime_1.jsx)(BatteryOptimizer_1.default, { onProfileChange: handlePowerProfileChange, onOptimizationApply: handleOptimizationApply, className: "w-full" }), (0, jsx_runtime_1.jsxs)("div", { className: "mt-6 p-4 bg-blue-50 rounded-lg", children: [(0, jsx_runtime_1.jsx)("h4", { className: "font-medium text-blue-900 mb-2", children: "\u4F18\u5316\u5EFA\u8BAE" }), (0, jsx_runtime_1.jsxs)("ul", { className: "text-sm text-blue-800 space-y-1", children: [(0, jsx_runtime_1.jsx)("li", { children: "\u2022 \u5728\u4F4E\u7535\u91CF\u65F6\u81EA\u52A8\u5207\u6362\u5230\u7701\u7535\u6A21\u5F0F" }), (0, jsx_runtime_1.jsx)("li", { children: "\u2022 \u51CF\u5C11\u540E\u53F0\u4F4D\u7F6E\u66F4\u65B0\u9891\u7387\u53EF\u5EF6\u957F\u7EED\u822A" }), (0, jsx_runtime_1.jsx)("li", { children: "\u2022 \u542F\u7528\u7F13\u5B58\u53EF\u51CF\u5C11\u7F51\u7EDC\u8BF7\u6C42\u6B21\u6570" }), (0, jsx_runtime_1.jsx)("li", { children: "\u2022 \u964D\u4F4E\u96F7\u8FBE\u626B\u63CF\u7CBE\u5EA6\u53EF\u8282\u7701\u5904\u7406\u5668\u8D44\u6E90" })] })] })] })] }) })] })] }));
};
exports.default = AdvancedLBSComponents;
//# sourceMappingURL=AdvancedLBSComponents.js.map