"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const notificationStore_1 = __importDefault(require("../../stores/notificationStore"));
const NotificationCenter_1 = __importDefault(require("./NotificationCenter"));
const NotificationButton = ({ className = '', showLabel = false }) => {
    const { unreadCount, isConnected } = (0, notificationStore_1.default)();
    const [isOpen, setIsOpen] = (0, react_1.useState)(false);
    const [isAnimating, setIsAnimating] = (0, react_1.useState)(false);
    (0, react_1.useEffect)(() => {
        if (unreadCount > 0) {
            setIsAnimating(true);
            const timer = setTimeout(() => setIsAnimating(false), 1000);
            return () => clearTimeout(timer);
        }
        return undefined;
    }, [unreadCount]);
    const handleClick = () => {
        setIsOpen(!isOpen);
    };
    const handleClose = () => {
        setIsOpen(false);
    };
    return ((0, jsx_runtime_1.jsxs)(jsx_runtime_1.Fragment, { children: [(0, jsx_runtime_1.jsxs)("button", { onClick: handleClick, className: `relative flex items-center space-x-2 rounded-lg p-2 transition-all hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${isAnimating ? 'animate-pulse' : ''} ${className}`, title: "\u901A\u77E5\u4E2D\u5FC3", children: [(0, jsx_runtime_1.jsxs)("div", { className: "relative", children: [unreadCount > 0 ? ((0, jsx_runtime_1.jsx)(lucide_react_1.BellRing, { className: `h-5 w-5 text-gray-600 ${isAnimating ? 'animate-bounce' : ''}` })) : ((0, jsx_runtime_1.jsx)(lucide_react_1.Bell, { className: "h-5 w-5 text-gray-600" })), unreadCount > 0 && ((0, jsx_runtime_1.jsx)("span", { className: `absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-xs font-medium text-white ${isAnimating ? 'animate-ping' : ''}`, children: unreadCount > 99 ? '99+' : unreadCount })), (0, jsx_runtime_1.jsx)("div", { className: `absolute -bottom-1 -right-1 h-2 w-2 rounded-full ${isConnected ? 'bg-green-400' : 'bg-red-400'}` })] }), showLabel && ((0, jsx_runtime_1.jsxs)("span", { className: "text-sm font-medium text-gray-700", children: ["\u901A\u77E5", unreadCount > 0 && ((0, jsx_runtime_1.jsxs)("span", { className: "ml-1 text-red-500", children: ["(", unreadCount, ")"] }))] }))] }), (0, jsx_runtime_1.jsx)(NotificationCenter_1.default, { isOpen: isOpen, onClose: handleClose })] }));
};
exports.default = NotificationButton;
//# sourceMappingURL=NotificationButton.js.map