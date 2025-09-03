"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const DistanceIndicator = ({ userLocation, targets, selectedTargetId, className = '', onTargetSelect, showNavigation = true, maxDisplayTargets = 5, sortBy = 'distance' }) => {
    const [distanceInfos, setDistanceInfos] = (0, react_1.useState)(new Map());
    const [selectedTarget, setSelectedTarget] = (0, react_1.useState)(null);
    const [compassHeading, setCompassHeading] = (0, react_1.useState)(0);
    const [isCompassSupported, setIsCompassSupported] = (0, react_1.useState)(false);
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
    const bearingToDirection = (bearing) => {
        const directions = [
            '北', '东北偏北', '东北', '东北偏东',
            '东', '东南偏东', '东南', '东南偏南',
            '南', '西南偏南', '西南', '西南偏西',
            '西', '西北偏西', '西北', '西北偏北'
        ];
        const index = Math.round(bearing / 22.5) % 16;
        return directions[index] || '北';
    };
    const estimateWalkTime = (distance) => {
        const walkingSpeed = 5000;
        return Math.round((distance / walkingSpeed) * 60);
    };
    const estimateDriveTime = (distance) => {
        const drivingSpeed = 30000;
        return Math.round((distance / drivingSpeed) * 60);
    };
    const formatDistance = (distance) => {
        if (distance < 1000) {
            return `${Math.round(distance)}m`;
        }
        else {
            return `${(distance / 1000).toFixed(1)}km`;
        }
    };
    const formatTime = (minutes) => {
        if (minutes < 60) {
            return `${minutes}分钟`;
        }
        else {
            const hours = Math.floor(minutes / 60);
            const mins = minutes % 60;
            return `${hours}小时${mins > 0 ? mins + '分钟' : ''}`;
        }
    };
    const initCompass = () => {
        if ('DeviceOrientationEvent' in window) {
            setIsCompassSupported(true);
            const handleOrientation = (event) => {
                if (event.alpha !== null) {
                    setCompassHeading(360 - event.alpha);
                }
            };
            if (typeof DeviceOrientationEvent.requestPermission === 'function') {
                DeviceOrientationEvent.requestPermission()
                    .then((response) => {
                    if (response === 'granted') {
                        window.addEventListener('deviceorientation', handleOrientation);
                    }
                })
                    .catch(() => {
                    setIsCompassSupported(false);
                });
            }
            else {
                window.addEventListener('deviceorientation', handleOrientation);
            }
            return () => {
                window.removeEventListener('deviceorientation', handleOrientation);
            };
        }
        else {
            setIsCompassSupported(false);
            return undefined;
        }
    };
    (0, react_1.useEffect)(() => {
        const newDistanceInfos = new Map();
        targets.forEach(target => {
            const distance = calculateDistance(userLocation, target.location);
            const bearing = calculateBearing(userLocation, target.location);
            const direction = bearingToDirection(bearing);
            const estimatedWalkTime = estimateWalkTime(distance);
            const estimatedDriveTime = estimateDriveTime(distance);
            newDistanceInfos.set(target.id, {
                distance,
                bearing,
                direction,
                estimatedWalkTime,
                estimatedDriveTime
            });
        });
        setDistanceInfos(newDistanceInfos);
    }, [userLocation, targets]);
    (0, react_1.useEffect)(() => {
        if (selectedTargetId) {
            const target = targets.find(t => t.id === selectedTargetId);
            setSelectedTarget(target || null);
        }
        else {
            setSelectedTarget(null);
        }
    }, [selectedTargetId, targets]);
    (0, react_1.useEffect)(() => {
        const cleanup = initCompass();
        return cleanup;
    }, []);
    const sortedTargets = [...targets].sort((a, b) => {
        const infoA = distanceInfos.get(a.id);
        const infoB = distanceInfos.get(b.id);
        if (!infoA || !infoB)
            return 0;
        switch (sortBy) {
            case 'distance':
                return infoA.distance - infoB.distance;
            case 'reward':
                return (b.reward || 0) - (a.reward || 0);
            case 'name':
                return a.name.localeCompare(b.name);
            default:
                return 0;
        }
    }).slice(0, maxDisplayTargets);
    const handleTargetClick = (target) => {
        setSelectedTarget(target);
        onTargetSelect?.(target);
    };
    const getArrowRotation = (bearing) => {
        return isCompassSupported ? bearing - compassHeading : bearing;
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: `bg-white rounded-lg shadow-lg ${className}`, children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between p-4 border-b border-gray-200", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Navigation, { className: "h-5 w-5 text-blue-500" }), (0, jsx_runtime_1.jsx)("h3", { className: "text-lg font-semibold text-gray-900", children: "\u8DDD\u79BB\u6307\u793A\u5668" })] }), isCompassSupported && ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2 text-sm text-gray-600", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Compass, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)("span", { children: [Math.round(compassHeading), "\u00B0"] })] }))] }), selectedTarget && ((0, jsx_runtime_1.jsx)("div", { className: "p-4 bg-blue-50 border-b border-gray-200", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-start justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex-1", children: [(0, jsx_runtime_1.jsx)("h4", { className: "font-semibold text-gray-900", children: selectedTarget.name }), selectedTarget.description && ((0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600 mt-1", children: selectedTarget.description })), distanceInfos.has(selectedTarget.id) && ((0, jsx_runtime_1.jsxs)("div", { className: "mt-2 grid grid-cols-2 gap-4 text-sm", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u8DDD\u79BB:" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 font-medium", children: formatDistance(distanceInfos.get(selectedTarget.id).distance) })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u65B9\u5411:" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 font-medium", children: distanceInfos.get(selectedTarget.id).direction })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u6B65\u884C:" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 font-medium", children: formatTime(distanceInfos.get(selectedTarget.id).estimatedWalkTime) })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u9A7E\u8F66:" }), (0, jsx_runtime_1.jsx)("span", { className: "ml-2 font-medium", children: formatTime(distanceInfos.get(selectedTarget.id).estimatedDriveTime) })] })] }))] }), distanceInfos.has(selectedTarget.id) && ((0, jsx_runtime_1.jsxs)("div", { className: "ml-4 flex flex-col items-center", children: [(0, jsx_runtime_1.jsx)("div", { className: "w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center transform transition-transform duration-300", style: {
                                        transform: `rotate(${getArrowRotation(distanceInfos.get(selectedTarget.id).bearing)}deg)`
                                    }, children: (0, jsx_runtime_1.jsx)(lucide_react_1.Navigation, { className: "h-6 w-6 text-white" }) }), (0, jsx_runtime_1.jsxs)("span", { className: "text-xs text-gray-600 mt-1", children: [Math.round(distanceInfos.get(selectedTarget.id).bearing), "\u00B0"] })] }))] }) })), (0, jsx_runtime_1.jsxs)("div", { className: "p-4", children: [(0, jsx_runtime_1.jsx)("div", { className: "space-y-3", children: sortedTargets.map(target => {
                            const distanceInfo = distanceInfos.get(target.id);
                            if (!distanceInfo)
                                return null;
                            const isSelected = selectedTarget?.id === target.id;
                            return ((0, jsx_runtime_1.jsx)("div", { onClick: () => handleTargetClick(target), className: `p-3 rounded-lg border cursor-pointer transition-colors ${isSelected
                                    ? 'border-blue-500 bg-blue-50'
                                    : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'}`, children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex-1", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: `w-2 h-2 rounded-full ${target.type === 'geofence' ? 'bg-yellow-500' :
                                                                target.type === 'poi' ? 'bg-blue-500' : 'bg-green-500'}` }), (0, jsx_runtime_1.jsx)("h5", { className: "font-medium text-gray-900", children: target.name }), target.reward && ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-1 text-green-600", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Award, { className: "h-3 w-3" }), (0, jsx_runtime_1.jsxs)("span", { className: "text-xs font-medium", children: ["+", target.reward] })] }))] }), (0, jsx_runtime_1.jsxs)("div", { className: "mt-1 flex items-center space-x-4 text-sm text-gray-600", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-1", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.MapPin, { className: "h-3 w-3" }), (0, jsx_runtime_1.jsx)("span", { children: formatDistance(distanceInfo.distance) })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-1", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Compass, { className: "h-3 w-3" }), (0, jsx_runtime_1.jsx)("span", { children: distanceInfo.direction })] }), showNavigation && ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-1", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Clock, { className: "h-3 w-3" }), (0, jsx_runtime_1.jsx)("span", { children: formatTime(distanceInfo.estimatedWalkTime) })] }))] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "ml-3 flex flex-col items-center", children: [(0, jsx_runtime_1.jsx)("div", { className: `w-8 h-8 rounded-full flex items-center justify-center transform transition-transform duration-300 ${isSelected ? 'bg-blue-500' : 'bg-gray-400'}`, style: {
                                                        transform: `rotate(${getArrowRotation(distanceInfo.bearing)}deg)`
                                                    }, children: (0, jsx_runtime_1.jsx)(lucide_react_1.Navigation, { className: "h-4 w-4 text-white" }) }), (0, jsx_runtime_1.jsxs)("span", { className: "text-xs text-gray-500 mt-1", children: [Math.round(distanceInfo.bearing), "\u00B0"] })] })] }) }, target.id));
                        }) }), targets.length === 0 && ((0, jsx_runtime_1.jsxs)("div", { className: "text-center py-8 text-gray-500", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Target, { className: "h-8 w-8 mx-auto mb-2" }), (0, jsx_runtime_1.jsx)("p", { children: "\u6682\u65E0\u76EE\u6807\u5730\u70B9" })] }))] })] }));
};
exports.default = DistanceIndicator;
//# sourceMappingURL=DistanceIndicator.js.map