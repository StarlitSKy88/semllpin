"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const GeofenceMap = ({ center, geofences, userLocation, className = '', onGeofenceClick, showUserAccuracy = true, interactive = true }) => {
    const canvasRef = (0, react_1.useRef)(null);
    const [selectedGeofence, setSelectedGeofence] = (0, react_1.useState)(null);
    const [mapScale, setMapScale] = (0, react_1.useState)(1);
    const [mapOffset, setMapOffset] = (0, react_1.useState)({ x: 0, y: 0 });
    const [isDragging, setIsDragging] = (0, react_1.useState)(false);
    const [lastMousePos, setLastMousePos] = (0, react_1.useState)({ x: 0, y: 0 });
    const MAP_SIZE = 400;
    const DEFAULT_ZOOM = 0.001;
    const MIN_ZOOM = 0.0001;
    const MAX_ZOOM = 0.01;
    const coordToCanvas = (longitude, latitude) => {
        const x = ((longitude - center[0]) / DEFAULT_ZOOM) * mapScale + MAP_SIZE / 2 + mapOffset.x;
        const y = ((center[1] - latitude) / DEFAULT_ZOOM) * mapScale + MAP_SIZE / 2 + mapOffset.y;
        return { x, y };
    };
    const metersToPixels = (meters) => {
        return (meters / (DEFAULT_ZOOM * 111000)) * mapScale;
    };
    const drawMap = () => {
        const canvas = canvasRef.current;
        if (!canvas)
            return;
        const ctx = canvas.getContext('2d');
        if (!ctx)
            return;
        ctx.clearRect(0, 0, MAP_SIZE, MAP_SIZE);
        ctx.strokeStyle = '#f0f0f0';
        ctx.lineWidth = 1;
        const gridSize = 50;
        for (let i = 0; i <= MAP_SIZE; i += gridSize) {
            ctx.beginPath();
            ctx.moveTo(i, 0);
            ctx.lineTo(i, MAP_SIZE);
            ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(0, i);
            ctx.lineTo(MAP_SIZE, i);
            ctx.stroke();
        }
        geofences.forEach((geofence) => {
            const pos = coordToCanvas(geofence.longitude, geofence.latitude);
            const radiusPixels = metersToPixels(geofence.radius);
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, radiusPixels, 0, 2 * Math.PI);
            let fillColor, strokeColor;
            switch (geofence.rewardType) {
                case 'discovery':
                    fillColor = 'rgba(255, 193, 7, 0.2)';
                    strokeColor = '#ffc107';
                    break;
                case 'checkin':
                    fillColor = 'rgba(0, 123, 255, 0.2)';
                    strokeColor = '#007bff';
                    break;
                case 'duration':
                    fillColor = 'rgba(40, 167, 69, 0.2)';
                    strokeColor = '#28a745';
                    break;
                case 'social':
                    fillColor = 'rgba(108, 117, 125, 0.2)';
                    strokeColor = '#6c757d';
                    break;
                default:
                    fillColor = 'rgba(108, 117, 125, 0.2)';
                    strokeColor = '#6c757d';
            }
            ctx.fillStyle = fillColor;
            ctx.fill();
            ctx.strokeStyle = strokeColor;
            ctx.lineWidth = selectedGeofence?.id === geofence.id ? 3 : 2;
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, 4, 0, 2 * Math.PI);
            ctx.fillStyle = strokeColor;
            ctx.fill();
            ctx.fillStyle = '#333';
            ctx.font = '12px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(geofence.name, pos.x, pos.y - radiusPixels - 10);
            ctx.font = '10px Arial';
            ctx.fillStyle = '#666';
            ctx.fillText(`${geofence.baseReward}分`, pos.x, pos.y + radiusPixels + 15);
        });
        if (userLocation) {
            const userPos = coordToCanvas(userLocation.longitude, userLocation.latitude);
            if (showUserAccuracy && userLocation.accuracy) {
                const accuracyPixels = metersToPixels(userLocation.accuracy);
                ctx.beginPath();
                ctx.arc(userPos.x, userPos.y, accuracyPixels, 0, 2 * Math.PI);
                ctx.fillStyle = 'rgba(59, 130, 246, 0.1)';
                ctx.fill();
                ctx.strokeStyle = '#3b82f6';
                ctx.lineWidth = 1;
                ctx.setLineDash([5, 5]);
                ctx.stroke();
                ctx.setLineDash([]);
            }
            ctx.beginPath();
            ctx.arc(userPos.x, userPos.y, 8, 0, 2 * Math.PI);
            ctx.fillStyle = '#3b82f6';
            ctx.fill();
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth = 2;
            ctx.stroke();
            const pulseRadius = 12 + Math.sin(Date.now() / 200) * 4;
            ctx.beginPath();
            ctx.arc(userPos.x, userPos.y, pulseRadius, 0, 2 * Math.PI);
            ctx.strokeStyle = 'rgba(59, 130, 246, 0.5)';
            ctx.lineWidth = 2;
            ctx.stroke();
        }
        const scaleLength = 100;
        const scaleMeters = Math.round((scaleLength / mapScale) * DEFAULT_ZOOM * 111000);
        ctx.fillStyle = '#333';
        ctx.font = '12px Arial';
        ctx.textAlign = 'left';
        ctx.fillText(`${scaleMeters}m`, 10, MAP_SIZE - 30);
        ctx.strokeStyle = '#333';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(10, MAP_SIZE - 20);
        ctx.lineTo(10 + scaleLength, MAP_SIZE - 20);
        ctx.stroke();
    };
    const handleCanvasClick = (event) => {
        if (!interactive)
            return;
        const canvas = canvasRef.current;
        if (!canvas)
            return;
        const rect = canvas.getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        for (const geofence of geofences) {
            const pos = coordToCanvas(geofence.longitude, geofence.latitude);
            const radiusPixels = metersToPixels(geofence.radius);
            const distance = Math.sqrt((x - pos.x) ** 2 + (y - pos.y) ** 2);
            if (distance <= radiusPixels) {
                setSelectedGeofence(geofence);
                onGeofenceClick?.(geofence);
                return;
            }
        }
        setSelectedGeofence(null);
    };
    const handleMouseDown = (event) => {
        if (!interactive)
            return;
        setIsDragging(true);
        setLastMousePos({ x: event.clientX, y: event.clientY });
    };
    const handleMouseMove = (event) => {
        if (!interactive || !isDragging)
            return;
        const deltaX = event.clientX - lastMousePos.x;
        const deltaY = event.clientY - lastMousePos.y;
        setMapOffset(prev => ({
            x: prev.x + deltaX,
            y: prev.y + deltaY
        }));
        setLastMousePos({ x: event.clientX, y: event.clientY });
    };
    const handleMouseUp = () => {
        setIsDragging(false);
    };
    const handleWheel = (event) => {
        if (!interactive)
            return;
        event.preventDefault();
        const zoomFactor = event.deltaY > 0 ? 0.9 : 1.1;
        const newScale = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, mapScale * zoomFactor));
        setMapScale(newScale);
    };
    const resetView = () => {
        setMapScale(1);
        setMapOffset({ x: 0, y: 0 });
        setSelectedGeofence(null);
    };
    (0, react_1.useEffect)(() => {
        drawMap();
    }, [center, geofences, userLocation, mapScale, mapOffset, selectedGeofence]);
    (0, react_1.useEffect)(() => {
        const animate = () => {
            drawMap();
            requestAnimationFrame(animate);
        };
        const animationId = requestAnimationFrame(animate);
        return () => cancelAnimationFrame(animationId);
    }, []);
    return ((0, jsx_runtime_1.jsxs)("div", { className: `relative bg-gray-100 rounded-lg overflow-hidden ${className}`, children: [(0, jsx_runtime_1.jsx)("canvas", { ref: canvasRef, width: MAP_SIZE, height: MAP_SIZE, className: "w-full h-full cursor-pointer", onClick: handleCanvasClick, onMouseDown: handleMouseDown, onMouseMove: handleMouseMove, onMouseUp: handleMouseUp, onMouseLeave: handleMouseUp, onWheel: handleWheel }), interactive && ((0, jsx_runtime_1.jsxs)("div", { className: "absolute top-2 right-2 flex flex-col space-y-1", children: [(0, jsx_runtime_1.jsx)("button", { onClick: () => setMapScale(prev => Math.min(MAX_ZOOM, prev * 1.2)), className: "bg-white hover:bg-gray-50 border border-gray-300 rounded p-1 shadow-sm", title: "\u653E\u5927", children: (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-bold", children: "+" }) }), (0, jsx_runtime_1.jsx)("button", { onClick: () => setMapScale(prev => Math.max(MIN_ZOOM, prev * 0.8)), className: "bg-white hover:bg-gray-50 border border-gray-300 rounded p-1 shadow-sm", title: "\u7F29\u5C0F", children: (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-bold", children: "\u2212" }) }), (0, jsx_runtime_1.jsx)("button", { onClick: resetView, className: "bg-white hover:bg-gray-50 border border-gray-300 rounded p-1 shadow-sm", title: "\u91CD\u7F6E\u89C6\u56FE", children: (0, jsx_runtime_1.jsx)(lucide_react_1.Target, { className: "h-4 w-4" }) })] })), (0, jsx_runtime_1.jsxs)("div", { className: "absolute bottom-2 left-2 bg-white bg-opacity-90 rounded p-2 text-xs space-y-1", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: "w-3 h-3 bg-blue-500 rounded-full" }), (0, jsx_runtime_1.jsx)("span", { children: "\u7528\u6237\u4F4D\u7F6E" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: "w-3 h-3 border-2 border-yellow-500 rounded-full" }), (0, jsx_runtime_1.jsx)("span", { children: "\u53D1\u73B0\u5956\u52B1" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: "w-3 h-3 border-2 border-blue-500 rounded-full" }), (0, jsx_runtime_1.jsx)("span", { children: "\u7B7E\u5230\u5956\u52B1" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: "w-3 h-3 border-2 border-green-500 rounded-full" }), (0, jsx_runtime_1.jsx)("span", { children: "\u505C\u7559\u5956\u52B1" })] })] }), selectedGeofence && ((0, jsx_runtime_1.jsx)("div", { className: "absolute top-2 left-2 bg-white rounded-lg shadow-lg p-4 max-w-xs", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-start justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex-1", children: [(0, jsx_runtime_1.jsx)("h3", { className: "font-semibold text-gray-900", children: selectedGeofence.name }), selectedGeofence.description && ((0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-600 mt-1", children: selectedGeofence.description })), (0, jsx_runtime_1.jsxs)("div", { className: "mt-2 space-y-1 text-sm", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u5956\u52B1\u7C7B\u578B:" }), (0, jsx_runtime_1.jsx)("span", { className: "font-medium", children: selectedGeofence.rewardType })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u57FA\u7840\u5956\u52B1:" }), (0, jsx_runtime_1.jsxs)("span", { className: "font-medium text-green-600", children: [selectedGeofence.baseReward, " \u5206"] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u534A\u5F84:" }), (0, jsx_runtime_1.jsxs)("span", { className: "font-medium", children: [selectedGeofence.radius, "m"] })] }), selectedGeofence.distance !== undefined && ((0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-gray-600", children: "\u8DDD\u79BB:" }), (0, jsx_runtime_1.jsxs)("span", { className: "font-medium", children: [Math.round(selectedGeofence.distance), "m"] })] }))] })] }), (0, jsx_runtime_1.jsx)("button", { onClick: () => setSelectedGeofence(null), className: "text-gray-400 hover:text-gray-600 ml-2", children: "\u00D7" })] }) })), (0, jsx_runtime_1.jsxs)("div", { className: "absolute bottom-2 right-2 bg-white bg-opacity-90 rounded p-2 text-xs", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-1", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Info, { className: "h-3 w-3" }), (0, jsx_runtime_1.jsxs)("span", { children: ["\u7F29\u653E: ", (mapScale * 100).toFixed(0), "%"] })] }), userLocation?.accuracy && ((0, jsx_runtime_1.jsxs)("div", { className: "text-gray-600", children: ["\u7CBE\u5EA6: \u00B1", Math.round(userLocation.accuracy), "m"] }))] })] }));
};
exports.default = GeofenceMap;
//# sourceMappingURL=GeofenceMap.js.map