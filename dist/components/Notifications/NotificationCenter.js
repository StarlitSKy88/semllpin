"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const notificationStore_1 = __importDefault(require("../../stores/notificationStore"));
const date_fns_1 = require("date-fns");
const locale_1 = require("date-fns/locale");
const NotificationCenter = ({ isOpen, onClose }) => {
    const { notifications, unreadCount, isConnected, markAsRead, markAllAsRead, removeNotification, clearAllNotifications, } = (0, notificationStore_1.default)();
    const [filter, setFilter] = (0, react_1.useState)('all');
    const [showSettings, setShowSettings] = (0, react_1.useState)(false);
    const filteredNotifications = notifications.filter(notification => {
        if (filter === 'all')
            return true;
        if (filter === 'unread')
            return !notification.read;
        return notification.type === filter;
    });
    const getConnectionStatus = () => {
        if (isConnected) {
            return { icon: lucide_react_1.Wifi, color: 'text-green-500', text: '已连接' };
        }
        else {
            return { icon: lucide_react_1.WifiOff, color: 'text-red-500', text: '未连接' };
        }
    };
    const connectionStatus = getConnectionStatus();
    const ConnectionIcon = connectionStatus.icon;
    const getNotificationIcon = (type) => {
        switch (type) {
            case 'reward':
                return '🎉';
            case 'geofence':
                return '📍';
            case 'achievement':
                return '🏆';
            case 'system':
                return 'ℹ️';
            default:
                return '🔔';
        }
    };
    const getNotificationColor = (type) => {
        switch (type) {
            case 'reward':
                return 'border-l-yellow-500 bg-yellow-50';
            case 'geofence':
                return 'border-l-blue-500 bg-blue-50';
            case 'achievement':
                return 'border-l-purple-500 bg-purple-50';
            case 'system':
                return 'border-l-gray-500 bg-gray-50';
            default:
                return 'border-l-gray-400 bg-gray-50';
        }
    };
    if (!isOpen)
        return null;
    return ((0, jsx_runtime_1.jsxs)("div", { className: "fixed inset-0 z-50 overflow-hidden", children: [(0, jsx_runtime_1.jsx)("div", { className: "absolute inset-0 bg-black bg-opacity-50", onClick: onClose }), (0, jsx_runtime_1.jsxs)("div", { className: "absolute right-0 top-0 h-full w-full max-w-md bg-white shadow-xl", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between border-b border-gray-200 p-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Bell, { className: "h-5 w-5 text-gray-600" }), (0, jsx_runtime_1.jsx)("h2", { className: "text-lg font-semibold text-gray-900", children: "\u901A\u77E5\u4E2D\u5FC3" }), unreadCount > 0 && ((0, jsx_runtime_1.jsx)("span", { className: "rounded-full bg-red-500 px-2 py-1 text-xs text-white", children: unreadCount }))] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsxs)("div", { className: `flex items-center space-x-1 ${connectionStatus.color}`, children: [(0, jsx_runtime_1.jsx)(ConnectionIcon, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { className: "text-xs", children: connectionStatus.text })] }), (0, jsx_runtime_1.jsx)("button", { onClick: () => setShowSettings(!showSettings), className: "rounded-lg p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600", children: (0, jsx_runtime_1.jsx)(lucide_react_1.Settings, { className: "h-4 w-4" }) }), (0, jsx_runtime_1.jsx)("button", { onClick: onClose, className: "rounded-lg p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600", children: (0, jsx_runtime_1.jsx)(lucide_react_1.X, { className: "h-4 w-4" }) })] })] }), showSettings && ((0, jsx_runtime_1.jsx)(NotificationSettings, { onClose: () => setShowSettings(false) })), (0, jsx_runtime_1.jsx)("div", { className: "border-b border-gray-200 p-4", children: (0, jsx_runtime_1.jsx)("div", { className: "flex space-x-2 overflow-x-auto", children: [
                                { key: 'all', label: '全部' },
                                { key: 'unread', label: '未读' },
                                { key: 'reward', label: '奖励' },
                                { key: 'geofence', label: '地点' },
                                { key: 'achievement', label: '成就' },
                                { key: 'system', label: '系统' }
                            ].map(({ key, label }) => ((0, jsx_runtime_1.jsxs)("button", { onClick: () => setFilter(key), className: `whitespace-nowrap rounded-full px-3 py-1 text-sm font-medium transition-colors ${filter === key
                                    ? 'bg-blue-100 text-blue-700'
                                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`, children: [label, key === 'unread' && unreadCount > 0 && ((0, jsx_runtime_1.jsxs)("span", { className: "ml-1 text-xs", children: ["(", unreadCount, ")"] }))] }, key))) }) }), notifications.length > 0 && ((0, jsx_runtime_1.jsx)("div", { className: "border-b border-gray-200 p-4", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex space-x-2", children: [(0, jsx_runtime_1.jsxs)("button", { onClick: markAllAsRead, disabled: unreadCount === 0, className: "flex items-center space-x-1 rounded-lg bg-blue-100 px-3 py-1 text-sm text-blue-700 hover:bg-blue-200 disabled:opacity-50 disabled:cursor-not-allowed", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.CheckCheck, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u5168\u90E8\u5DF2\u8BFB" })] }), (0, jsx_runtime_1.jsxs)("button", { onClick: clearAllNotifications, className: "flex items-center space-x-1 rounded-lg bg-red-100 px-3 py-1 text-sm text-red-700 hover:bg-red-200", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Trash2, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u6E05\u7A7A\u5168\u90E8" })] })] }) })), (0, jsx_runtime_1.jsx)("div", { className: "flex-1 overflow-y-auto", children: filteredNotifications.length === 0 ? ((0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col items-center justify-center p-8 text-gray-500", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Bell, { className: "h-12 w-12 text-gray-300" }), (0, jsx_runtime_1.jsx)("p", { className: "mt-2 text-sm", children: filter === 'unread' ? '没有未读通知' : '暂无通知' })] })) : ((0, jsx_runtime_1.jsx)("div", { className: "space-y-2 p-4", children: filteredNotifications.map((notification) => ((0, jsx_runtime_1.jsx)(NotificationItem, { notification: notification, onMarkAsRead: markAsRead, onRemove: removeNotification, getIcon: getNotificationIcon, getColor: getNotificationColor }, notification.id))) })) })] })] }));
};
const NotificationItem = ({ notification, onMarkAsRead, onRemove, getIcon, getColor }) => {
    const handleClick = () => {
        if (!notification.read) {
            onMarkAsRead(notification.id);
        }
    };
    return ((0, jsx_runtime_1.jsx)("div", { className: `border-l-4 rounded-lg p-3 transition-all hover:shadow-md cursor-pointer ${getColor(notification.type)} ${notification.read ? 'opacity-75' : 'shadow-sm'}`, onClick: handleClick, children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-start justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-start space-x-3 flex-1", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-lg", children: getIcon(notification.type) }), (0, jsx_runtime_1.jsxs)("div", { className: "flex-1 min-w-0", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("h4", { className: `text-sm font-medium ${notification.read ? 'text-gray-600' : 'text-gray-900'}`, children: notification.title }), !notification.read && ((0, jsx_runtime_1.jsx)("div", { className: "h-2 w-2 rounded-full bg-blue-500" }))] }), (0, jsx_runtime_1.jsx)("p", { className: `mt-1 text-sm ${notification.read ? 'text-gray-500' : 'text-gray-700'}`, children: notification.message }), (0, jsx_runtime_1.jsx)("p", { className: "mt-1 text-xs text-gray-400", children: (0, date_fns_1.formatDistanceToNow)(new Date(notification.timestamp), {
                                        addSuffix: true,
                                        locale: locale_1.zhCN
                                    }) }), notification.type === 'reward' && notification.data && ((0, jsx_runtime_1.jsx)("div", { className: "mt-2 text-xs text-gray-600", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsxs)("span", { children: ["\u57FA\u7840: ", notification.data.breakdown?.baseReward || 0] }), (0, jsx_runtime_1.jsxs)("span", { children: ["\u8870\u51CF: \u00D7", notification.data.breakdown?.timeDecayFactor || 1] }), notification.data.breakdown?.firstDiscovererBonus > 0 && ((0, jsx_runtime_1.jsxs)("span", { className: "text-yellow-600", children: ["\u9996\u53D1: +", notification.data.breakdown.firstDiscovererBonus] }))] }) }))] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-1 ml-2", children: [!notification.read && ((0, jsx_runtime_1.jsx)("button", { onClick: (e) => {
                                e.stopPropagation();
                                onMarkAsRead(notification.id);
                            }, className: "rounded-lg p-1 text-gray-400 hover:bg-white hover:text-gray-600", title: "\u6807\u8BB0\u4E3A\u5DF2\u8BFB", children: (0, jsx_runtime_1.jsx)(lucide_react_1.Check, { className: "h-3 w-3" }) })), (0, jsx_runtime_1.jsx)("button", { onClick: (e) => {
                                e.stopPropagation();
                                onRemove(notification.id);
                            }, className: "rounded-lg p-1 text-gray-400 hover:bg-white hover:text-red-600", title: "\u5220\u9664\u901A\u77E5", children: (0, jsx_runtime_1.jsx)(lucide_react_1.X, { className: "h-3 w-3" }) })] })] }) }));
};
const NotificationSettings = ({ onClose: _onClose }) => {
    const { settings, updateSettings } = (0, notificationStore_1.default)();
    const handleToggle = (key) => {
        updateSettings({ [key]: !settings[key] });
    };
    return ((0, jsx_runtime_1.jsx)("div", { className: "border-b border-gray-200 bg-gray-50 p-4", children: (0, jsx_runtime_1.jsxs)("div", { className: "space-y-3", children: [(0, jsx_runtime_1.jsx)("h3", { className: "text-sm font-medium text-gray-900", children: "\u901A\u77E5\u8BBE\u7F6E" }), [
                    { key: 'enabled', label: '启用通知' },
                    { key: 'sound', label: '声音提醒' },
                    { key: 'vibration', label: '振动提醒' },
                    { key: 'browserNotifications', label: '浏览器通知' },
                    { key: 'rewardNotifications', label: '奖励通知' },
                    { key: 'geofenceNotifications', label: '地点通知' },
                    { key: 'achievementNotifications', label: '成就通知' },
                    { key: 'systemNotifications', label: '系统通知' }
                ].map(({ key, label }) => ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-sm text-gray-700", children: label }), (0, jsx_runtime_1.jsx)("button", { onClick: () => handleToggle(key), className: `relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${settings[key]
                                ? 'bg-blue-600'
                                : 'bg-gray-300'}`, children: (0, jsx_runtime_1.jsx)("span", { className: `inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${settings[key]
                                    ? 'translate-x-5'
                                    : 'translate-x-1'}` }) })] }, key)))] }) }));
};
exports.default = NotificationCenter;
//# sourceMappingURL=NotificationCenter.js.map