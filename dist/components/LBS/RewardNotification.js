"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const lbsStore_1 = require("../../stores/lbsStore");
const RewardNotificationItem = ({ notification, onClose, isVisible }) => {
    const [isAnimating, setIsAnimating] = (0, react_1.useState)(false);
    (0, react_1.useEffect)(() => {
        if (isVisible) {
            setIsAnimating(true);
            const timer = setTimeout(() => {
                onClose();
            }, 5000);
            return () => clearTimeout(timer);
        }
        return undefined;
    }, [isVisible, onClose]);
    const getRewardTypeInfo = (type) => {
        switch (type) {
            case 'discovery':
                return {
                    icon: lucide_react_1.Star,
                    label: '首次发现',
                    color: 'text-yellow-500',
                    bgColor: 'bg-yellow-50',
                    borderColor: 'border-yellow-200'
                };
            case 'checkin':
                return {
                    icon: lucide_react_1.MapPin,
                    label: '签到奖励',
                    color: 'text-blue-500',
                    bgColor: 'bg-blue-50',
                    borderColor: 'border-blue-200'
                };
            case 'stay':
                return {
                    icon: lucide_react_1.Clock,
                    label: '停留奖励',
                    color: 'text-green-500',
                    bgColor: 'bg-green-50',
                    borderColor: 'border-green-200'
                };
            case 'social':
                return {
                    icon: lucide_react_1.Award,
                    label: '社交奖励',
                    color: 'text-purple-500',
                    bgColor: 'bg-purple-50',
                    borderColor: 'border-purple-200'
                };
            default:
                return {
                    icon: lucide_react_1.Award,
                    label: '奖励',
                    color: 'text-gray-500',
                    bgColor: 'bg-gray-50',
                    borderColor: 'border-gray-200'
                };
        }
    };
    const typeInfo = getRewardTypeInfo(notification.type);
    const IconComponent = typeInfo.icon;
    return ((0, jsx_runtime_1.jsxs)("div", { className: `
        transform transition-all duration-500 ease-out
        ${isVisible && isAnimating
            ? 'translate-x-0 opacity-100 scale-100'
            : 'translate-x-full opacity-0 scale-95'}
        ${typeInfo.bgColor} ${typeInfo.borderColor}
        border rounded-lg shadow-lg p-4 mb-3 relative overflow-hidden
      `, children: [(0, jsx_runtime_1.jsx)("div", { className: "absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-20 transform -skew-x-12 animate-pulse" }), (0, jsx_runtime_1.jsx)("button", { onClick: onClose, className: "absolute top-2 right-2 text-gray-400 hover:text-gray-600 transition-colors", children: (0, jsx_runtime_1.jsx)(lucide_react_1.X, { className: "h-4 w-4" }) }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-start space-x-3", children: [(0, jsx_runtime_1.jsx)("div", { className: `flex-shrink-0 ${typeInfo.color}`, children: (0, jsx_runtime_1.jsx)(IconComponent, { className: "h-6 w-6" }) }), (0, jsx_runtime_1.jsxs)("div", { className: "flex-1 min-w-0", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsxs)("h4", { className: "text-lg font-bold text-gray-900", children: ["+", notification.amount, " \u5206"] }), (0, jsx_runtime_1.jsx)("span", { className: `text-sm font-medium ${typeInfo.color}`, children: typeInfo.label })] }), (0, jsx_runtime_1.jsxs)("p", { className: "text-sm text-gray-700 mt-1", children: ["\u5728 ", (0, jsx_runtime_1.jsx)("span", { className: "font-medium", children: notification.geofenceName }), " \u83B7\u5F97\u5956\u52B1"] }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-500 mt-1", children: new Date(notification.timestamp).toLocaleTimeString() }), notification.breakdown && ((0, jsx_runtime_1.jsxs)("div", { className: "mt-2 text-xs text-gray-600 space-y-1", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between", children: [(0, jsx_runtime_1.jsx)("span", { children: "\u57FA\u7840\u5956\u52B1:" }), (0, jsx_runtime_1.jsxs)("span", { children: [notification.breakdown.baseAmount, " \u5206"] })] }), notification.breakdown.timeDecayFactor !== 1 && ((0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between", children: [(0, jsx_runtime_1.jsx)("span", { children: "\u65F6\u95F4\u8870\u51CF:" }), (0, jsx_runtime_1.jsxs)("span", { children: ["\u00D7", notification.breakdown.timeDecayFactor.toFixed(2)] })] })), notification.breakdown.isFirstDiscoverer && ((0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between text-yellow-600", children: [(0, jsx_runtime_1.jsx)("span", { children: "\u9996\u6B21\u53D1\u73B0\u5956\u52B1:" }), (0, jsx_runtime_1.jsx)("span", { children: "\u00D72.0" })] })), notification.breakdown.bonusMultiplier !== 1 && ((0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between text-green-600", children: [(0, jsx_runtime_1.jsx)("span", { children: "\u989D\u5916\u5956\u52B1:" }), (0, jsx_runtime_1.jsxs)("span", { children: ["\u00D7", notification.breakdown.bonusMultiplier] })] }))] }))] })] }), (0, jsx_runtime_1.jsx)("div", { className: "absolute bottom-0 left-0 right-0 h-1 bg-gray-200", children: (0, jsx_runtime_1.jsx)("div", { className: `h-full ${typeInfo.color.replace('text-', 'bg-')} transition-all duration-5000 ease-linear`, style: {
                        width: isVisible ? '0%' : '100%',
                        transition: isVisible ? 'width 5s linear' : 'none'
                    } }) })] }));
};
const RewardNotification = () => {
    const { recentRewards } = (0, lbsStore_1.useLBSStore)();
    const [notifications, setNotifications] = (0, react_1.useState)([]);
    const [visibleNotifications, setVisibleNotifications] = (0, react_1.useState)(new Set());
    (0, react_1.useEffect)(() => {
        if (recentRewards.length > 0) {
            const latestReward = recentRewards[0];
            if (!latestReward)
                return;
            const notificationId = `${latestReward.id}_${Date.now()}`;
            const existingNotification = notifications.find(n => n.id.startsWith(latestReward.id));
            if (!existingNotification) {
                const newNotification = {
                    id: notificationId,
                    type: 'reward',
                    amount: latestReward.finalPoints || 0,
                    geofenceName: latestReward.geofenceName || '未知位置',
                    timestamp: latestReward.timestamp || new Date().toISOString(),
                    breakdown: latestReward.metadata
                };
                setNotifications(prev => [newNotification, ...prev.slice(0, 4)]);
                setVisibleNotifications(prev => new Set([...prev, notificationId]));
            }
        }
        return undefined;
    }, [recentRewards, notifications]);
    const closeNotification = (notificationId) => {
        setVisibleNotifications(prev => {
            const newSet = new Set(prev);
            newSet.delete(notificationId);
            return newSet;
        });
        setTimeout(() => {
            setNotifications(prev => prev.filter(n => n.id !== notificationId));
        }, 500);
    };
    const clearAllNotifications = () => {
        setVisibleNotifications(new Set());
        setTimeout(() => {
            setNotifications([]);
        }, 500);
    };
    if (notifications.length === 0) {
        return null;
    }
    return ((0, jsx_runtime_1.jsxs)("div", { className: "fixed top-4 right-4 z-50 w-80 max-w-sm", children: [notifications.length > 1 && ((0, jsx_runtime_1.jsx)("div", { className: "mb-2 flex justify-end", children: (0, jsx_runtime_1.jsx)("button", { onClick: clearAllNotifications, className: "text-xs text-gray-500 hover:text-gray-700 bg-white rounded px-2 py-1 shadow-sm border", children: "\u6E05\u9664\u6240\u6709" }) })), (0, jsx_runtime_1.jsx)("div", { className: "space-y-2", children: notifications.map((notification) => ((0, jsx_runtime_1.jsx)(RewardNotificationItem, { notification: notification, onClose: () => closeNotification(notification.id), isVisible: visibleNotifications.has(notification.id) }, notification.id))) })] }));
};
exports.default = RewardNotification;
//# sourceMappingURL=RewardNotification.js.map