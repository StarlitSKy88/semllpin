"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const BatteryOptimizer = ({ onProfileChange, onOptimizationApply, className = '' }) => {
    const [batteryInfo, setBatteryInfo] = (0, react_1.useState)(null);
    const [currentProfile, setCurrentProfile] = (0, react_1.useState)(null);
    const [isSupported, setIsSupported] = (0, react_1.useState)(false);
    const [powerUsageStats, setPowerUsageStats] = (0, react_1.useState)({
        totalUsage: 0,
        locationRequests: 0,
        networkRequests: 0,
        lastOptimization: null
    });
    const [autoOptimization, setAutoOptimization] = (0, react_1.useState)(true);
    const powerProfiles = [
        {
            id: 'performance',
            name: '性能模式',
            description: '最佳性能，高精度定位，适合短时间使用',
            settings: {
                locationUpdateInterval: 5000,
                accuracyLevel: 'high',
                backgroundSync: true,
                radarScanInterval: 2000,
                maxConcurrentRequests: 5,
                cacheEnabled: true
            },
            batteryThreshold: 50,
            estimatedBatteryLife: 2
        },
        {
            id: 'balanced',
            name: '平衡模式',
            description: '性能与续航平衡，适合日常使用',
            settings: {
                locationUpdateInterval: 15000,
                accuracyLevel: 'medium',
                backgroundSync: true,
                radarScanInterval: 5000,
                maxConcurrentRequests: 3,
                cacheEnabled: true
            },
            batteryThreshold: 30,
            estimatedBatteryLife: 4
        },
        {
            id: 'power_saver',
            name: '省电模式',
            description: '最大化续航时间，降低更新频率',
            settings: {
                locationUpdateInterval: 60000,
                accuracyLevel: 'low',
                backgroundSync: false,
                radarScanInterval: 15000,
                maxConcurrentRequests: 1,
                cacheEnabled: true
            },
            batteryThreshold: 15,
            estimatedBatteryLife: 8
        },
        {
            id: 'ultra_saver',
            name: '超级省电',
            description: '极限省电，仅基础功能',
            settings: {
                locationUpdateInterval: 300000,
                accuracyLevel: 'low',
                backgroundSync: false,
                radarScanInterval: 60000,
                maxConcurrentRequests: 1,
                cacheEnabled: true
            },
            batteryThreshold: 10,
            estimatedBatteryLife: 12
        }
    ];
    const getBatteryInfo = (0, react_1.useCallback)(async () => {
        if ('getBattery' in navigator) {
            try {
                const battery = await navigator.getBattery();
                const info = {
                    level: Math.round(battery.level * 100),
                    charging: battery.charging,
                    chargingTime: battery.chargingTime,
                    dischargingTime: battery.dischargingTime
                };
                setBatteryInfo(info);
                setIsSupported(true);
                const updateBatteryInfo = () => {
                    setBatteryInfo({
                        level: Math.round(battery.level * 100),
                        charging: battery.charging,
                        chargingTime: battery.chargingTime,
                        dischargingTime: battery.dischargingTime
                    });
                };
                battery.addEventListener('levelchange', updateBatteryInfo);
                battery.addEventListener('chargingchange', updateBatteryInfo);
                return () => {
                    battery.removeEventListener('levelchange', updateBatteryInfo);
                    battery.removeEventListener('chargingchange', updateBatteryInfo);
                };
            }
            catch (error) {
                console.warn('Battery API not supported:', error);
                setIsSupported(false);
                return undefined;
            }
        }
        else {
            setIsSupported(false);
            return undefined;
        }
    }, []);
    const getRecommendedProfile = (0, react_1.useCallback)((batteryLevel) => {
        if (batteryLevel <= 10) {
            return powerProfiles.find(p => p.id === 'ultra_saver');
        }
        else if (batteryLevel <= 20) {
            return powerProfiles.find(p => p.id === 'power_saver');
        }
        else if (batteryLevel <= 50) {
            return powerProfiles.find(p => p.id === 'balanced');
        }
        else {
            return powerProfiles.find(p => p.id === 'performance');
        }
    }, [powerProfiles]);
    const applyOptimization = (0, react_1.useCallback)((profile) => {
        setCurrentProfile(profile);
        onProfileChange?.(profile);
        onOptimizationApply?.(profile.settings);
        setPowerUsageStats(prev => ({
            ...prev,
            lastOptimization: new Date()
        }));
        localStorage.setItem('lbs_power_profile', JSON.stringify(profile));
    }, [onProfileChange, onOptimizationApply]);
    const performAutoOptimization = (0, react_1.useCallback)(() => {
        if (!batteryInfo || !autoOptimization)
            return;
        const recommendedProfile = getRecommendedProfile(batteryInfo.level);
        if (!currentProfile || currentProfile.id !== recommendedProfile.id) {
            applyOptimization(recommendedProfile);
        }
    }, [batteryInfo, autoOptimization, currentProfile, getRecommendedProfile, applyOptimization]);
    const selectProfile = (profileId) => {
        const profile = powerProfiles.find(p => p.id === profileId);
        if (profile) {
            applyOptimization(profile);
        }
    };
    const getBatteryColor = (level, charging) => {
        if (charging)
            return 'text-green-500';
        if (level <= 10)
            return 'text-red-500';
        if (level <= 20)
            return 'text-orange-500';
        if (level <= 50)
            return 'text-yellow-500';
        return 'text-green-500';
    };
    const getBatteryIcon = (_level, charging) => {
        if (charging)
            return (0, jsx_runtime_1.jsx)(lucide_react_1.Battery, { className: "h-4 w-4" });
        return (0, jsx_runtime_1.jsx)(lucide_react_1.Battery, { className: "h-4 w-4" });
    };
    const formatTime = (seconds) => {
        if (!seconds || seconds === Infinity)
            return '未知';
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}小时${minutes}分钟`;
    };
    (0, react_1.useEffect)(() => {
        const initBattery = async () => {
            const cleanup = await getBatteryInfo();
            return cleanup;
        };
        initBattery();
        const savedProfile = localStorage.getItem('lbs_power_profile');
        if (savedProfile) {
            try {
                const profile = JSON.parse(savedProfile);
                setCurrentProfile(profile);
            }
            catch (error) {
                console.warn('Failed to parse saved power profile:', error);
            }
        }
    }, [getBatteryInfo]);
    (0, react_1.useEffect)(() => {
        if (autoOptimization) {
            performAutoOptimization();
        }
    }, [batteryInfo?.level, autoOptimization, performAutoOptimization]);
    (0, react_1.useEffect)(() => {
        if (!isSupported) {
            setBatteryInfo({
                level: 65,
                charging: false
            });
        }
    }, [isSupported]);
    return ((0, jsx_runtime_1.jsxs)("div", { className: `bg-white rounded-lg shadow-lg ${className}`, children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between p-4 border-b border-gray-200", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Battery, { className: "h-5 w-5 text-green-500" }), (0, jsx_runtime_1.jsx)("h3", { className: "text-lg font-semibold text-gray-900", children: "\u7535\u6C60\u4F18\u5316" })] }), !isSupported && ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-1 text-orange-500", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertTriangle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm", children: "API\u4E0D\u652F\u6301" })] }))] }), batteryInfo && ((0, jsx_runtime_1.jsxs)("div", { className: "p-4 border-b border-gray-200", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between mb-3", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: getBatteryColor(batteryInfo.level, batteryInfo.charging), children: getBatteryIcon(batteryInfo.level, batteryInfo.charging) }), (0, jsx_runtime_1.jsxs)("span", { className: "text-lg font-semibold", children: [batteryInfo.level, "%"] }), batteryInfo.charging && ((0, jsx_runtime_1.jsx)("span", { className: "text-sm text-green-600", children: "\u5145\u7535\u4E2D" }))] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-right text-sm text-gray-600", children: [batteryInfo.charging && batteryInfo.chargingTime && ((0, jsx_runtime_1.jsxs)("div", { children: ["\u5145\u6EE1\u9700\u8981: ", formatTime(batteryInfo.chargingTime)] })), !batteryInfo.charging && batteryInfo.dischargingTime && ((0, jsx_runtime_1.jsxs)("div", { children: ["\u5269\u4F59\u65F6\u95F4: ", formatTime(batteryInfo.dischargingTime)] }))] })] }), (0, jsx_runtime_1.jsx)("div", { className: "w-full bg-gray-200 rounded-full h-2", children: (0, jsx_runtime_1.jsx)("div", { className: `h-2 rounded-full transition-all duration-300 ${batteryInfo.charging ? 'bg-green-500' :
                                batteryInfo.level <= 10 ? 'bg-red-500' :
                                    batteryInfo.level <= 20 ? 'bg-orange-500' :
                                        batteryInfo.level <= 50 ? 'bg-yellow-500' : 'bg-green-500'}`, style: { width: `${batteryInfo.level}%` } }) })] })), (0, jsx_runtime_1.jsx)("div", { className: "p-4 border-b border-gray-200", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h4", { className: "font-medium text-gray-900", children: "\u81EA\u52A8\u4F18\u5316" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600", children: "\u6839\u636E\u7535\u6C60\u7535\u91CF\u81EA\u52A8\u8C03\u6574\u6027\u80FD\u8BBE\u7F6E" })] }), (0, jsx_runtime_1.jsx)("button", { onClick: () => setAutoOptimization(!autoOptimization), className: `relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${autoOptimization ? 'bg-blue-500' : 'bg-gray-300'}`, children: (0, jsx_runtime_1.jsx)("span", { className: `inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${autoOptimization ? 'translate-x-6' : 'translate-x-1'}` }) })] }) }), (0, jsx_runtime_1.jsxs)("div", { className: "p-4", children: [(0, jsx_runtime_1.jsx)("h4", { className: "font-medium text-gray-900 mb-3", children: "\u7535\u6E90\u914D\u7F6E\u6587\u4EF6" }), (0, jsx_runtime_1.jsx)("div", { className: "space-y-2", children: powerProfiles.map(profile => {
                            const isActive = currentProfile?.id === profile.id;
                            const isRecommended = batteryInfo &&
                                getRecommendedProfile(batteryInfo.level).id === profile.id;
                            return ((0, jsx_runtime_1.jsx)("div", { onClick: () => selectProfile(profile.id), className: `p-3 rounded-lg border cursor-pointer transition-colors ${isActive
                                    ? 'border-blue-500 bg-blue-50'
                                    : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'}`, children: (0, jsx_runtime_1.jsx)("div", { className: "flex items-center justify-between", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex-1", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("h5", { className: "font-medium text-gray-900", children: profile.name }), isActive && ((0, jsx_runtime_1.jsx)(lucide_react_1.CheckCircle, { className: "h-4 w-4 text-blue-500" })), isRecommended && !isActive && ((0, jsx_runtime_1.jsx)("span", { className: "px-2 py-1 text-xs bg-green-100 text-green-800 rounded-full", children: "\u63A8\u8350" }))] }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600 mt-1", children: profile.description }), (0, jsx_runtime_1.jsxs)("div", { className: "mt-2 grid grid-cols-2 gap-2 text-xs text-gray-500", children: [(0, jsx_runtime_1.jsxs)("div", { children: ["\u66F4\u65B0\u95F4\u9694: ", profile.settings.locationUpdateInterval / 1000, "\u79D2"] }), (0, jsx_runtime_1.jsxs)("div", { children: ["\u7CBE\u5EA6: ", profile.settings.accuracyLevel] }), (0, jsx_runtime_1.jsxs)("div", { children: ["\u9884\u4F30\u7EED\u822A: ", profile.estimatedBatteryLife, "\u5C0F\u65F6"] }), (0, jsx_runtime_1.jsxs)("div", { children: ["\u7535\u6C60\u9608\u503C: ", profile.batteryThreshold, "%"] })] })] }) }) }, profile.id));
                        }) })] }), (0, jsx_runtime_1.jsxs)("div", { className: "p-4 border-t border-gray-200", children: [(0, jsx_runtime_1.jsx)("h4", { className: "font-medium text-gray-900 mb-3", children: "\u4F7F\u7528\u7EDF\u8BA1" }), (0, jsx_runtime_1.jsxs)("div", { className: "grid grid-cols-2 gap-4 text-sm", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Smartphone, { className: "h-4 w-4 text-gray-500" }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("div", { className: "text-gray-600", children: "\u4F4D\u7F6E\u8BF7\u6C42" }), (0, jsx_runtime_1.jsx)("div", { className: "font-medium", children: powerUsageStats.locationRequests })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertTriangle, { className: "h-4 w-4 text-gray-500" }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("div", { className: "text-gray-600", children: "\u7F51\u7EDC\u8BF7\u6C42" }), (0, jsx_runtime_1.jsx)("div", { className: "font-medium", children: powerUsageStats.networkRequests })] })] })] }), powerUsageStats.lastOptimization && ((0, jsx_runtime_1.jsxs)("div", { className: "mt-3 flex items-center space-x-2 text-sm text-gray-600", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Clock, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)("span", { children: ["\u4E0A\u6B21\u4F18\u5316: ", powerUsageStats.lastOptimization.toLocaleTimeString()] })] }))] })] }));
};
exports.default = BatteryOptimizer;
//# sourceMappingURL=BatteryOptimizer.js.map