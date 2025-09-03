"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const RewardHistory = ({ className = '' }) => {
    const [rewards, setRewards] = (0, react_1.useState)([]);
    const [stats, setStats] = (0, react_1.useState)(null);
    const [loading, setLoading] = (0, react_1.useState)(true);
    const [error, setError] = (0, react_1.useState)(null);
    const [currentPage, setCurrentPage] = (0, react_1.useState)(1);
    const [totalPages, setTotalPages] = (0, react_1.useState)(1);
    const [filters, setFilters] = (0, react_1.useState)({
        rewardType: '',
        dateRange: '7d',
        sortBy: 'timestamp',
        sortOrder: 'desc'
    });
    const [showFilters, setShowFilters] = (0, react_1.useState)(false);
    const [selectedPeriod, setSelectedPeriod] = (0, react_1.useState)('week');
    const pageSize = 20;
    const fetchRewards = async () => {
        try {
            setLoading(true);
            setError(null);
            const params = new URLSearchParams({
                page: currentPage.toString(),
                limit: pageSize.toString(),
                ...(filters.rewardType && { type: filters.rewardType }),
                ...(filters.dateRange !== 'all' && { dateRange: filters.dateRange }),
                sortBy: filters.sortBy,
                sortOrder: filters.sortOrder
            });
            const response = await fetch(`/api/lbs/rewards/history?${params}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) {
                throw new Error(`获取奖励历史失败: ${response.status}`);
            }
            const data = await response.json();
            setRewards(data.rewards || []);
            setTotalPages(Math.ceil((data.total || 0) / pageSize));
        }
        catch (err) {
            console.error('获取奖励历史失败:', err);
            setError(err instanceof Error ? err.message : '获取奖励历史失败');
        }
        finally {
            setLoading(false);
        }
    };
    const fetchStats = async () => {
        try {
            const response = await fetch(`/api/lbs/rewards/stats?period=${selectedPeriod}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) {
                throw new Error(`获取奖励统计失败: ${response.status}`);
            }
            const data = await response.json();
            setStats(data);
        }
        catch (err) {
            console.error('获取奖励统计失败:', err);
        }
    };
    const formatRewardType = (type) => {
        const typeMap = {
            discovery: '发现奖励',
            checkin: '签到奖励',
            stay: '停留奖励',
            social: '社交奖励'
        };
        return typeMap[type] || type;
    };
    const formatDate = (dateString) => {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffHours / 24);
        if (diffHours < 1) {
            const diffMinutes = Math.floor(diffMs / (1000 * 60));
            return `${diffMinutes}分钟前`;
        }
        else if (diffHours < 24) {
            return `${diffHours}小时前`;
        }
        else if (diffDays < 7) {
            return `${diffDays}天前`;
        }
        else {
            return date.toLocaleDateString('zh-CN', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
        }
    };
    const getRewardTypeColor = (type) => {
        const colorMap = {
            discovery: 'text-yellow-600 bg-yellow-100',
            checkin: 'text-blue-600 bg-blue-100',
            stay: 'text-green-600 bg-green-100',
            social: 'text-purple-600 bg-purple-100'
        };
        return colorMap[type] || 'text-gray-600 bg-gray-100';
    };
    const handleFilterChange = (key, value) => {
        setFilters(prev => ({ ...prev, [key]: value }));
        setCurrentPage(1);
    };
    const resetFilters = () => {
        setFilters({
            rewardType: '',
            dateRange: '7d',
            sortBy: 'timestamp',
            sortOrder: 'desc'
        });
        setCurrentPage(1);
    };
    (0, react_1.useEffect)(() => {
        fetchRewards();
    }, [currentPage, filters]);
    (0, react_1.useEffect)(() => {
        fetchStats();
    }, [selectedPeriod]);
    if (loading && rewards.length === 0) {
        return ((0, jsx_runtime_1.jsx)("div", { className: `bg-white rounded-lg shadow-sm p-6 ${className}`, children: (0, jsx_runtime_1.jsxs)("div", { className: "animate-pulse space-y-4", children: [(0, jsx_runtime_1.jsx)("div", { className: "h-6 bg-gray-200 rounded w-1/3" }), (0, jsx_runtime_1.jsx)("div", { className: "space-y-3", children: [...Array(5)].map((_, i) => ((0, jsx_runtime_1.jsx)("div", { className: "h-16 bg-gray-200 rounded" }, i))) })] }) }));
    }
    return ((0, jsx_runtime_1.jsxs)("div", { className: `bg-white rounded-lg shadow-sm ${className}`, children: [stats && ((0, jsx_runtime_1.jsxs)("div", { className: "p-6 border-b border-gray-200", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between mb-4", children: [(0, jsx_runtime_1.jsx)("h2", { className: "text-lg font-semibold text-gray-900", children: "\u5956\u52B1\u7EDF\u8BA1" }), (0, jsx_runtime_1.jsxs)("select", { value: selectedPeriod, onChange: (e) => setSelectedPeriod(e.target.value), className: "text-sm border border-gray-300 rounded px-3 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500", children: [(0, jsx_runtime_1.jsx)("option", { value: "today", children: "\u4ECA\u65E5" }), (0, jsx_runtime_1.jsx)("option", { value: "week", children: "\u672C\u5468" }), (0, jsx_runtime_1.jsx)("option", { value: "month", children: "\u672C\u6708" }), (0, jsx_runtime_1.jsx)("option", { value: "all", children: "\u5168\u90E8" })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "grid grid-cols-2 md:grid-cols-4 gap-4 mb-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "text-center", children: [(0, jsx_runtime_1.jsx)("div", { className: "text-2xl font-bold text-blue-600", children: stats.totalRewards }), (0, jsx_runtime_1.jsx)("div", { className: "text-sm text-gray-600", children: "\u603B\u5956\u52B1\u6B21\u6570" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-center", children: [(0, jsx_runtime_1.jsx)("div", { className: "text-2xl font-bold text-green-600", children: stats.totalAmount }), (0, jsx_runtime_1.jsx)("div", { className: "text-sm text-gray-600", children: "\u603B\u5956\u52B1\u79EF\u5206" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-center", children: [(0, jsx_runtime_1.jsx)("div", { className: "text-2xl font-bold text-purple-600", children: stats.averagePerDay.toFixed(1) }), (0, jsx_runtime_1.jsx)("div", { className: "text-sm text-gray-600", children: "\u65E5\u5747\u79EF\u5206" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-center", children: [(0, jsx_runtime_1.jsxs)("div", { className: "text-2xl font-bold text-orange-600", children: ["#", stats.rank] }), (0, jsx_runtime_1.jsx)("div", { className: "text-sm text-gray-600", children: "\u6392\u540D" })] })] }), (0, jsx_runtime_1.jsx)("div", { className: "grid grid-cols-2 md:grid-cols-4 gap-2", children: Object.entries(stats.rewardsByType).map(([type, data]) => ((0, jsx_runtime_1.jsxs)("div", { className: `p-2 rounded-lg ${getRewardTypeColor(type)}`, children: [(0, jsx_runtime_1.jsx)("div", { className: "text-xs font-medium", children: formatRewardType(type) }), (0, jsx_runtime_1.jsxs)("div", { className: "text-sm font-bold", children: [data.count, "\u6B21 \u00B7 ", data.amount, "\u5206"] })] }, type))) })] })), (0, jsx_runtime_1.jsxs)("div", { className: "p-4 border-b border-gray-200", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsx)("h3", { className: "text-lg font-semibold text-gray-900", children: "\u5956\u52B1\u5386\u53F2" }), (0, jsx_runtime_1.jsxs)("button", { onClick: () => setShowFilters(!showFilters), className: "flex items-center space-x-1 text-sm text-gray-600 hover:text-gray-900", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Filter, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "\u7B5B\u9009" }), showFilters ? (0, jsx_runtime_1.jsx)(lucide_react_1.ChevronUp, { className: "h-4 w-4" }) : (0, jsx_runtime_1.jsx)(lucide_react_1.ChevronDown, { className: "h-4 w-4" })] })] }), showFilters && ((0, jsx_runtime_1.jsxs)("div", { className: "mt-4 grid grid-cols-1 md:grid-cols-4 gap-4", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "\u5956\u52B1\u7C7B\u578B" }), (0, jsx_runtime_1.jsxs)("select", { value: filters.rewardType, onChange: (e) => handleFilterChange('rewardType', e.target.value), className: "w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500", children: [(0, jsx_runtime_1.jsx)("option", { value: "", children: "\u5168\u90E8\u7C7B\u578B" }), (0, jsx_runtime_1.jsx)("option", { value: "discovery", children: "\u53D1\u73B0\u5956\u52B1" }), (0, jsx_runtime_1.jsx)("option", { value: "checkin", children: "\u7B7E\u5230\u5956\u52B1" }), (0, jsx_runtime_1.jsx)("option", { value: "duration", children: "\u505C\u7559\u5956\u52B1" }), (0, jsx_runtime_1.jsx)("option", { value: "social", children: "\u793E\u4EA4\u5956\u52B1" })] })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "\u65F6\u95F4\u8303\u56F4" }), (0, jsx_runtime_1.jsxs)("select", { value: filters.dateRange, onChange: (e) => handleFilterChange('dateRange', e.target.value), className: "w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500", children: [(0, jsx_runtime_1.jsx)("option", { value: "7d", children: "\u6700\u8FD17\u5929" }), (0, jsx_runtime_1.jsx)("option", { value: "30d", children: "\u6700\u8FD130\u5929" }), (0, jsx_runtime_1.jsx)("option", { value: "90d", children: "\u6700\u8FD190\u5929" }), (0, jsx_runtime_1.jsx)("option", { value: "all", children: "\u5168\u90E8\u65F6\u95F4" })] })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("label", { className: "block text-sm font-medium text-gray-700 mb-1", children: "\u6392\u5E8F\u65B9\u5F0F" }), (0, jsx_runtime_1.jsxs)("select", { value: filters.sortBy, onChange: (e) => handleFilterChange('sortBy', e.target.value), className: "w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500", children: [(0, jsx_runtime_1.jsx)("option", { value: "timestamp", children: "\u65F6\u95F4" }), (0, jsx_runtime_1.jsx)("option", { value: "amount", children: "\u5956\u52B1\u91D1\u989D" })] })] }), (0, jsx_runtime_1.jsx)("div", { className: "flex items-end", children: (0, jsx_runtime_1.jsx)("button", { onClick: resetFilters, className: "w-full bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded text-sm font-medium transition-colors", children: "\u91CD\u7F6E\u7B5B\u9009" }) })] }))] }), (0, jsx_runtime_1.jsxs)("div", { className: "divide-y divide-gray-200", children: [error && ((0, jsx_runtime_1.jsx)("div", { className: "p-4 bg-red-50 border-l-4 border-red-400", children: (0, jsx_runtime_1.jsx)("div", { className: "text-red-700", children: error }) })), rewards.length === 0 && !loading ? ((0, jsx_runtime_1.jsxs)("div", { className: "p-8 text-center text-gray-500", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Award, { className: "h-12 w-12 mx-auto mb-4 text-gray-300" }), (0, jsx_runtime_1.jsx)("p", { children: "\u6682\u65E0\u5956\u52B1\u8BB0\u5F55" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm mt-1", children: "\u5F00\u59CB\u63A2\u7D22\u9644\u8FD1\u7684\u5730\u7406\u56F4\u680F\u6765\u83B7\u5F97\u5956\u52B1\u5427\uFF01" })] })) : (rewards.map((reward) => ((0, jsx_runtime_1.jsx)("div", { className: "p-4 hover:bg-gray-50 cursor-pointer transition-colors", onClick: () => { }, children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-start justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex-1", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2 mb-1", children: [(0, jsx_runtime_1.jsx)("span", { className: `px-2 py-1 rounded-full text-xs font-medium ${getRewardTypeColor(reward.rewardType)}`, children: formatRewardType(reward.rewardType) }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm text-gray-600", children: formatDate(reward.timestamp) })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2 mb-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.MapPin, { className: "h-4 w-4 text-gray-400" }), (0, jsx_runtime_1.jsx)("span", { className: "font-medium text-gray-900", children: reward.geofenceName })] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-sm text-gray-600 space-y-1", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between", children: [(0, jsx_runtime_1.jsx)("span", { children: "\u57FA\u7840\u5956\u52B1:" }), (0, jsx_runtime_1.jsxs)("span", { children: [reward.baseReward, " \u5206"] })] }), reward.timeDecay !== 1 && ((0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between", children: [(0, jsx_runtime_1.jsx)("span", { children: "\u65F6\u95F4\u8870\u51CF:" }), (0, jsx_runtime_1.jsxs)("span", { children: ["\u00D7", reward.timeDecay.toFixed(2)] })] })), reward.firstDiscoveryBonus > 0 && ((0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between text-yellow-600", children: [(0, jsx_runtime_1.jsx)("span", { children: "\u9996\u6B21\u53D1\u73B0\u5956\u52B1:" }), (0, jsx_runtime_1.jsxs)("span", { children: ["+", reward.firstDiscoveryBonus, " \u5206"] })] }))] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-right", children: [(0, jsx_runtime_1.jsxs)("div", { className: "text-lg font-bold text-green-600", children: ["+", reward.finalPoints || 0] }), (0, jsx_runtime_1.jsx)("div", { className: "text-sm text-gray-500", children: "\u79EF\u5206" })] })] }) }, reward.id))))] }), totalPages > 1 && ((0, jsx_runtime_1.jsx)("div", { className: "p-4 border-t border-gray-200", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "text-sm text-gray-600", children: ["\u7B2C ", currentPage, " \u9875\uFF0C\u5171 ", totalPages, " \u9875"] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex space-x-2", children: [(0, jsx_runtime_1.jsx)("button", { onClick: () => setCurrentPage(prev => Math.max(1, prev - 1)), disabled: currentPage === 1, className: "px-3 py-1 border border-gray-300 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50", children: "\u4E0A\u4E00\u9875" }), (0, jsx_runtime_1.jsx)("button", { onClick: () => setCurrentPage(prev => Math.min(totalPages, prev + 1)), disabled: currentPage === totalPages, className: "px-3 py-1 border border-gray-300 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50", children: "\u4E0B\u4E00\u9875" })] })] }) })), loading && rewards.length > 0 && ((0, jsx_runtime_1.jsx)("div", { className: "p-4 text-center", children: (0, jsx_runtime_1.jsxs)("div", { className: "inline-flex items-center space-x-2 text-gray-600", children: [(0, jsx_runtime_1.jsx)("div", { className: "animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600" }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm", children: "\u52A0\u8F7D\u4E2D..." })] }) }))] }));
};
exports.default = RewardHistory;
//# sourceMappingURL=RewardHistory.js.map