"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const toast = {
    error: (message) => console.error('Toast error:', message),
    success: (message) => console.log('Toast success:', message),
    info: (message) => console.info('Toast info:', message),
};
const notificationStore_1 = __importDefault(require("../../stores/notificationStore"));
const NotificationButton_1 = __importDefault(require("../Notifications/NotificationButton"));
const authStore_1 = require("../../stores/authStore");
const lbsStore_1 = require("../../stores/lbsStore");
const RewardNotification_1 = __importDefault(require("./RewardNotification"));
const GeofenceMap_1 = __importDefault(require("./GeofenceMap"));
const AdvancedLBSComponents_1 = __importDefault(require("./AdvancedLBSComponents"));
const button_1 = require("../ui/button");
const card_1 = require("../ui/card");
const badge_1 = require("../ui/badge");
const tabs_1 = require("../ui/tabs");
const LBSRewardTracker = () => {
    const { user, token } = (0, authStore_1.useAuthStore)();
    const { isTracking, currentLocation, nearbyGeofences, recentRewards, setTracking, updateLocation, addReward, fetchNearbyGeofences, fetchRewardHistory } = (0, lbsStore_1.useLBSStore)();
    const { connectWebSocket, disconnectWebSocket, isConnected } = (0, notificationStore_1.default)();
    const [locationPermission, setLocationPermission] = (0, react_1.useState)('prompt');
    const [isOnline, setIsOnline] = (0, react_1.useState)(navigator.onLine);
    const [lastReportTime, setLastReportTime] = (0, react_1.useState)(null);
    const [reportInterval] = (0, react_1.useState)(30000);
    const [accuracy, setAccuracy] = (0, react_1.useState)(null);
    const [isReporting, setIsReporting] = (0, react_1.useState)(false);
    const [activeTab, setActiveTab] = (0, react_1.useState)('basic');
    const watchIdRef = (0, react_1.useRef)(null);
    const reportTimerRef = (0, react_1.useRef)(null);
    const pendingReportsRef = (0, react_1.useRef)([]);
    const checkLocationPermission = (0, react_1.useCallback)(async () => {
        if (!navigator.geolocation) {
            toast.error('您的设备不支持位置服务');
            return false;
        }
        try {
            const permission = await navigator.permissions.query({ name: 'geolocation' });
            setLocationPermission(permission.state);
            permission.addEventListener('change', () => {
                setLocationPermission(permission.state);
            });
            return permission.state === 'granted';
        }
        catch (error) {
            console.warn('无法检查位置权限:', error);
            return true;
        }
    }, []);
    const getCurrentLocation = (0, react_1.useCallback)(() => {
        return new Promise((resolve, reject) => {
            if (!navigator.geolocation) {
                reject(new Error('设备不支持位置服务'));
                return;
            }
            const options = {
                enableHighAccuracy: true,
                timeout: 15000,
                maximumAge: 60000
            };
            navigator.geolocation.getCurrentPosition((position) => {
                const locationData = {
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude,
                    accuracy: position.coords.accuracy,
                    altitude: position.coords.altitude ?? undefined,
                    heading: position.coords.heading ?? undefined,
                    speed: position.coords.speed ?? undefined,
                    timestamp: new Date().toISOString()
                };
                setAccuracy(position.coords.accuracy);
                resolve(locationData);
            }, (error) => {
                let errorMessage = '获取位置失败';
                switch (error.code) {
                    case error.PERMISSION_DENIED:
                        errorMessage = '位置权限被拒绝';
                        break;
                    case error.POSITION_UNAVAILABLE:
                        errorMessage = '位置信息不可用';
                        break;
                    case error.TIMEOUT:
                        errorMessage = '获取位置超时';
                        break;
                }
                reject(new Error(errorMessage));
            }, options);
        });
    }, []);
    const reportLocation = (0, react_1.useCallback)(async (locationData) => {
        if (!token || !user) {
            console.warn('用户未登录，跳过位置上报');
            return null;
        }
        try {
            setIsReporting(true);
            const response = await fetch('/api/lbs/location/report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(locationData)
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            const result = await response.json();
            if (result.success) {
                setLastReportTime(new Date());
                updateLocation({
                    latitude: locationData.latitude,
                    longitude: locationData.longitude,
                    accuracy: locationData.accuracy,
                    altitude: undefined,
                    heading: undefined,
                    speed: undefined,
                    timestamp: typeof locationData.timestamp === 'string' ? new Date(locationData.timestamp).getTime() : Date.now()
                });
                if (result.data.reward?.earned) {
                    addReward({
                        id: `temp_${Date.now()}`,
                        userId: user?.id || '',
                        geofenceId: result.data.geofenceDetection.geofences[0]?.id || '',
                        geofenceName: result.data.geofenceDetection.geofences[0]?.name || '未知地点',
                        rewardType: result.data.geofenceDetection.geofences[0]?.type || 'checkin',
                        baseReward: result.data.reward.amount,
                        timeDecay: 0,
                        firstDiscoveryBonus: 0,
                        extraReward: 0,
                        finalPoints: result.data.reward.amount,
                        latitude: locationData.latitude,
                        longitude: locationData.longitude,
                        timestamp: new Date().toISOString(),
                        metadata: result.data.reward.breakdown
                    });
                }
                return result;
            }
            else {
                throw new Error(result.message || '位置上报失败');
            }
        }
        catch (error) {
            console.error('位置上报错误:', error);
            if (!isOnline) {
                pendingReportsRef.current.push(locationData);
                toast.info('网络离线，位置数据已缓存');
            }
            else {
                toast.error(`位置上报失败: ${error instanceof Error ? error.message : '未知错误'}`);
            }
            return null;
        }
        finally {
            setIsReporting(false);
        }
    }, [token, user, isOnline, updateLocation, addReward]);
    const processPendingReports = (0, react_1.useCallback)(async () => {
        if (pendingReportsRef.current.length === 0 || !isOnline) {
            return;
        }
        const reports = [...pendingReportsRef.current];
        pendingReportsRef.current = [];
        for (const locationData of reports) {
            try {
                await reportLocation(locationData);
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
            catch (error) {
                pendingReportsRef.current.push(locationData);
                break;
            }
        }
        if (pendingReportsRef.current.length > 0) {
            toast.info(`还有 ${pendingReportsRef.current.length} 条位置数据待上报`);
        }
        else {
            toast.success('所有缓存的位置数据已上报完成');
        }
    }, [isOnline, reportLocation]);
    const startTracking = (0, react_1.useCallback)(async () => {
        try {
            const hasPermission = await checkLocationPermission();
            if (!hasPermission) {
                toast.error('需要位置权限才能开始追踪');
                return;
            }
            const initialLocation = await getCurrentLocation();
            const reportResult = await reportLocation(initialLocation);
            if (reportResult?.data.reward?.earned) {
                toast.success(`获得奖励: ${reportResult.data.reward.amount} 分！`);
            }
            reportTimerRef.current = setInterval(async () => {
                try {
                    const location = await getCurrentLocation();
                    const result = await reportLocation(location);
                    if (result?.data.reward?.earned) {
                        toast.success(`获得奖励: ${result.data.reward.amount} 分！`);
                    }
                }
                catch (error) {
                    console.error('定期位置上报失败:', error);
                }
            }, reportInterval);
            if (navigator.geolocation) {
                const options = {
                    enableHighAccuracy: true,
                    timeout: 10000,
                    maximumAge: 30000
                };
                watchIdRef.current = navigator.geolocation.watchPosition((position) => {
                    setAccuracy(position.coords.accuracy);
                    updateLocation({
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        accuracy: position.coords.accuracy,
                        altitude: position.coords.altitude || undefined,
                        heading: position.coords.heading || undefined,
                        speed: position.coords.speed || undefined,
                        timestamp: Date.now()
                    });
                }, (error) => {
                    console.error('位置监听错误:', error);
                }, options);
            }
            setTracking(true);
            toast.success('位置追踪已开始');
            fetchNearbyGeofences({
                latitude: initialLocation.latitude,
                longitude: initialLocation.longitude,
                accuracy: initialLocation.accuracy,
                altitude: initialLocation.altitude,
                heading: initialLocation.heading,
                speed: initialLocation.speed,
                timestamp: initialLocation.timestamp
            });
        }
        catch (error) {
            console.error('开始追踪失败:', error);
            toast.error(`开始追踪失败: ${error instanceof Error ? error.message : '未知错误'}`);
        }
    }, [checkLocationPermission, getCurrentLocation, reportLocation, reportInterval, setTracking, updateLocation, fetchNearbyGeofences]);
    const stopTracking = (0, react_1.useCallback)(() => {
        if (watchIdRef.current !== null) {
            navigator.geolocation.clearWatch(watchIdRef.current);
            watchIdRef.current = null;
        }
        if (reportTimerRef.current) {
            clearInterval(reportTimerRef.current);
            reportTimerRef.current = null;
        }
        setTracking(false);
        toast.info('位置追踪已停止');
    }, [setTracking]);
    const initializeWebSocket = (0, react_1.useCallback)(async () => {
        try {
            if (token && isOnline) {
                await connectWebSocket(token);
            }
        }
        catch (error) {
            console.error('WebSocket连接失败:', error);
        }
    }, [token, isOnline, connectWebSocket]);
    (0, react_1.useEffect)(() => {
        const handleOnline = () => {
            setIsOnline(true);
            toast.success('网络已连接');
            processPendingReports();
            initializeWebSocket();
        };
        const handleOffline = () => {
            setIsOnline(false);
            toast.warning('网络已断开，位置数据将缓存');
        };
        window.addEventListener('online', handleOnline);
        window.addEventListener('offline', handleOffline);
        return () => {
            window.removeEventListener('online', handleOnline);
            window.removeEventListener('offline', handleOffline);
        };
    }, [processPendingReports, initializeWebSocket]);
    (0, react_1.useEffect)(() => {
        initializeWebSocket();
        return () => {
            disconnectWebSocket();
        };
    }, [initializeWebSocket, disconnectWebSocket]);
    (0, react_1.useEffect)(() => {
        return () => {
            if (watchIdRef.current !== null) {
                navigator.geolocation.clearWatch(watchIdRef.current);
            }
            if (reportTimerRef.current) {
                clearInterval(reportTimerRef.current);
            }
        };
    }, []);
    const getAccuracyStatus = () => {
        if (!accuracy)
            return { text: '未知', color: 'text-gray-500' };
        if (accuracy <= 10)
            return { text: '高精度', color: 'text-green-500' };
        if (accuracy <= 50)
            return { text: '中等精度', color: 'text-yellow-500' };
        return { text: '低精度', color: 'text-red-500' };
    };
    const accuracyStatus = getAccuracyStatus();
    return ((0, jsx_runtime_1.jsxs)(card_1.Card, { className: "space-y-6", children: [(0, jsx_runtime_1.jsx)(card_1.CardHeader, { children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.MapPin, { className: "h-6 w-6 text-blue-500" }), (0, jsx_runtime_1.jsx)(card_1.CardTitle, { children: "LBS\u5956\u52B1\u8FFD\u8E2A" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(NotificationButton_1.default, {}), isOnline ? ((0, jsx_runtime_1.jsx)(lucide_react_1.Wifi, { className: "h-5 w-5 text-green-500" })) : ((0, jsx_runtime_1.jsx)(lucide_react_1.WifiOff, { className: "h-5 w-5 text-red-500" })), (0, jsx_runtime_1.jsx)("div", { className: `h-2 w-2 rounded-full ${isConnected ? 'bg-blue-500' : 'bg-gray-400'}`, title: isConnected ? 'WebSocket已连接' : 'WebSocket未连接' }), (0, jsx_runtime_1.jsx)(badge_1.Badge, { variant: isOnline ? 'success' : 'destructive', children: isOnline ? '在线' : '离线' })] })] }) }), (0, jsx_runtime_1.jsx)(card_1.CardContent, { children: (0, jsx_runtime_1.jsxs)(tabs_1.Tabs, { value: activeTab, onValueChange: setActiveTab, className: "w-full", children: [(0, jsx_runtime_1.jsxs)(tabs_1.TabsList, { className: "grid w-full grid-cols-2", children: [(0, jsx_runtime_1.jsxs)(tabs_1.TabsTrigger, { value: "basic", className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.MapPin, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u57FA\u7840\u8FFD\u8E2A" })] }), (0, jsx_runtime_1.jsxs)(tabs_1.TabsTrigger, { value: "advanced", className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Radar, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u9AD8\u7EA7\u529F\u80FD" })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-4", children: [(0, jsx_runtime_1.jsx)(card_1.Card, { children: (0, jsx_runtime_1.jsxs)(card_1.CardContent, { className: "p-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.MapPin, { className: "h-5 w-5 text-blue-500" }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-medium text-gray-700", children: "\u8FFD\u8E2A\u72B6\u6001" })] }), (0, jsx_runtime_1.jsx)("p", { className: `text-lg font-semibold mt-1 ${isTracking ? 'text-green-600' : 'text-gray-600'}`, children: isTracking ? '进行中' : '已停止' })] }) }), (0, jsx_runtime_1.jsx)(card_1.Card, { children: (0, jsx_runtime_1.jsxs)(card_1.CardContent, { className: "p-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Clock, { className: "h-5 w-5 text-orange-500" }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-medium text-gray-700", children: "\u6700\u540E\u4E0A\u62A5" })] }), (0, jsx_runtime_1.jsx)("p", { className: "text-lg font-semibold text-gray-600 mt-1", children: lastReportTime ? lastReportTime.toLocaleTimeString() : '未上报' })] }) }), (0, jsx_runtime_1.jsx)(card_1.Card, { children: (0, jsx_runtime_1.jsxs)(card_1.CardContent, { className: "p-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertTriangle, { className: "h-5 w-5 text-yellow-500" }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-medium text-gray-700", children: "\u4F4D\u7F6E\u7CBE\u5EA6" })] }), (0, jsx_runtime_1.jsxs)("p", { className: `text-lg font-semibold mt-1 ${accuracyStatus.color}`, children: [accuracyStatus.text, accuracy && ((0, jsx_runtime_1.jsxs)("span", { className: "text-sm text-gray-500 ml-1", children: ["(\u00B1", Math.round(accuracy), "m)"] }))] })] }) })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex space-x-4", children: [!isTracking ? ((0, jsx_runtime_1.jsx)(button_1.Button, { onClick: startTracking, disabled: !user || locationPermission === 'denied', className: "flex-1", size: "lg", children: "\u5F00\u59CB\u8FFD\u8E2A" })) : ((0, jsx_runtime_1.jsx)(button_1.Button, { onClick: stopTracking, variant: "destructive", className: "flex-1", size: "lg", children: "\u505C\u6B62\u8FFD\u8E2A" })), (0, jsx_runtime_1.jsx)(button_1.Button, { onClick: () => fetchRewardHistory(), disabled: !user, variant: "outline", size: "lg", children: "\u5237\u65B0\u5956\u52B1" })] }), locationPermission === 'denied' && ((0, jsx_runtime_1.jsx)(card_1.Card, { className: "border-red-200 bg-red-50", children: (0, jsx_runtime_1.jsxs)(card_1.CardContent, { className: "p-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertTriangle, { className: "h-5 w-5 text-red-500" }), (0, jsx_runtime_1.jsx)("span", { className: "text-red-700 font-medium", children: "\u4F4D\u7F6E\u6743\u9650\u88AB\u62D2\u7EDD" })] }), (0, jsx_runtime_1.jsx)("p", { className: "text-red-600 text-sm mt-1", children: "\u8BF7\u5728\u6D4F\u89C8\u5668\u8BBE\u7F6E\u4E2D\u5141\u8BB8\u4F4D\u7F6E\u8BBF\u95EE\u6743\u9650\uFF0C\u7136\u540E\u5237\u65B0\u9875\u9762\u3002" })] }) })), !isOnline && pendingReportsRef.current.length > 0 && ((0, jsx_runtime_1.jsx)(card_1.Card, { className: "border-yellow-200 bg-yellow-50", children: (0, jsx_runtime_1.jsxs)(card_1.CardContent, { className: "p-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.WifiOff, { className: "h-5 w-5 text-yellow-500" }), (0, jsx_runtime_1.jsx)("span", { className: "text-yellow-700 font-medium", children: "\u7F51\u7EDC\u79BB\u7EBF" })] }), (0, jsx_runtime_1.jsxs)("p", { className: "text-yellow-600 text-sm mt-1", children: ["\u6709 ", pendingReportsRef.current.length, " \u6761\u4F4D\u7F6E\u6570\u636E\u5F85\u4E0A\u62A5\uFF0C\u7F51\u7EDC\u6062\u590D\u540E\u5C06\u81EA\u52A8\u4E0A\u62A5\u3002"] })] }) })), isReporting && ((0, jsx_runtime_1.jsx)(card_1.Card, { className: "border-blue-200 bg-blue-50", children: (0, jsx_runtime_1.jsx)(card_1.CardContent, { className: "p-4", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: "animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500" }), (0, jsx_runtime_1.jsx)("span", { className: "text-blue-700 font-medium", children: "\u6B63\u5728\u4E0A\u62A5\u4F4D\u7F6E..." })] }) }) })), currentLocation && ((0, jsx_runtime_1.jsxs)(card_1.Card, { children: [(0, jsx_runtime_1.jsx)(card_1.CardHeader, { children: (0, jsx_runtime_1.jsx)(card_1.CardTitle, { className: "text-lg", children: "\u5F53\u524D\u4F4D\u7F6E" }) }), (0, jsx_runtime_1.jsx)(card_1.CardContent, { children: (0, jsx_runtime_1.jsxs)("div", { className: "grid grid-cols-2 gap-4 text-sm", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u7ECF\u5EA6:" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 font-mono", children: currentLocation.longitude.toFixed(6) })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u7EAC\u5EA6:" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 font-mono", children: currentLocation.latitude.toFixed(6) })] })] }) })] })), nearbyGeofences.length > 0 && ((0, jsx_runtime_1.jsxs)(card_1.Card, { children: [(0, jsx_runtime_1.jsx)(card_1.CardHeader, { children: (0, jsx_runtime_1.jsx)(card_1.CardTitle, { className: "text-lg", children: "\u9644\u8FD1\u5730\u7406\u56F4\u680F" }) }), (0, jsx_runtime_1.jsx)(card_1.CardContent, { children: (0, jsx_runtime_1.jsx)("div", { className: "space-y-2", children: nearbyGeofences.slice(0, 3).map((geofence) => ((0, jsx_runtime_1.jsx)(card_1.Card, { className: "p-3", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("p", { className: "font-medium text-gray-900", children: geofence.name }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600", children: geofence.description })] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-right space-y-1", children: [(0, jsx_runtime_1.jsxs)(badge_1.Badge, { variant: "outline", children: [Math.round(geofence.distance || 0), "m"] }), (0, jsx_runtime_1.jsxs)("p", { className: "text-xs text-gray-500", children: [geofence.baseReward, " \u5206"] })] })] }) }, geofence.id))) }) })] })), recentRewards.length > 0 && ((0, jsx_runtime_1.jsxs)(card_1.Card, { children: [(0, jsx_runtime_1.jsx)(card_1.CardHeader, { children: (0, jsx_runtime_1.jsx)(card_1.CardTitle, { className: "text-lg", children: "\u6700\u8FD1\u5956\u52B1" }) }), (0, jsx_runtime_1.jsx)(card_1.CardContent, { children: (0, jsx_runtime_1.jsx)("div", { className: "space-y-2", children: recentRewards.slice(0, 3).map((reward) => ((0, jsx_runtime_1.jsx)(card_1.Card, { className: "p-3", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Award, { className: "h-4 w-4 text-yellow-500" }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("p", { className: "font-medium text-gray-900", children: reward.geofenceName }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600", children: new Date(reward.timestamp).toLocaleString() })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-right space-y-1", children: [(0, jsx_runtime_1.jsxs)(badge_1.Badge, { variant: "success", className: "text-lg font-bold", children: ["+", reward.finalPoints] }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-500", children: reward.rewardType })] })] }) }, reward.id))) }) })] })), (0, jsx_runtime_1.jsx)(tabs_1.TabsContent, { value: "basic", className: "mt-4", children: currentLocation && ((0, jsx_runtime_1.jsx)(GeofenceMap_1.default, { center: [currentLocation.longitude, currentLocation.latitude], geofences: nearbyGeofences, userLocation: currentLocation, className: "h-64 rounded-lg" })) }), (0, jsx_runtime_1.jsx)(tabs_1.TabsContent, { value: "advanced", className: "mt-4", children: currentLocation && ((0, jsx_runtime_1.jsx)(AdvancedLBSComponents_1.default, { userLocation: {
                                    longitude: currentLocation.longitude,
                                    latitude: currentLocation.latitude
                                }, geofenceTargets: nearbyGeofences.map(geofence => ({
                                    id: geofence.id,
                                    name: geofence.name,
                                    location: {
                                        longitude: geofence.longitude,
                                        latitude: geofence.latitude
                                    },
                                    type: 'geofence',
                                    reward: geofence.baseReward,
                                    radius: geofence.radius,
                                    isActive: geofence.isActive
                                })) })) })] }) }), (0, jsx_runtime_1.jsx)(RewardNotification_1.default, {})] }));
};
exports.default = LBSRewardTracker;
//# sourceMappingURL=LBSRewardTracker.js.map