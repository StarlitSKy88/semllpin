"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const lucide_react_1 = require("lucide-react");
const RadarScanner = ({ isScanning, targets, maxRange = 1000, className = '', onTargetDetected, showGrid = true, scanSpeed = 1 }) => {
    const canvasRef = (0, react_1.useRef)(null);
    const animationRef = (0, react_1.useRef)(0);
    const [scanAngle, setScanAngle] = (0, react_1.useState)(0);
    const [detectedTargets, setDetectedTargets] = (0, react_1.useState)(new Set());
    const [pulseTargets, setPulseTargets] = (0, react_1.useState)(new Set());
    const RADAR_SIZE = 300;
    const CENTER = RADAR_SIZE / 2;
    const RADAR_RADIUS = CENTER - 20;
    const degToRad = (degrees) => (degrees * Math.PI) / 180;
    const distanceToRadius = (distance) => {
        return Math.min((distance / maxRange) * RADAR_RADIUS, RADAR_RADIUS);
    };
    const drawRadarBackground = (ctx) => {
        ctx.clearRect(0, 0, RADAR_SIZE, RADAR_SIZE);
        ctx.fillStyle = '#0a0a0a';
        ctx.fillRect(0, 0, RADAR_SIZE, RADAR_SIZE);
        ctx.strokeStyle = '#00ff00';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(CENTER, CENTER, RADAR_RADIUS, 0, 2 * Math.PI);
        ctx.stroke();
        if (showGrid) {
            for (let i = 1; i < 4; i++) {
                ctx.beginPath();
                ctx.arc(CENTER, CENTER, (RADAR_RADIUS / 4) * i, 0, 2 * Math.PI);
                ctx.stroke();
            }
            ctx.beginPath();
            ctx.moveTo(CENTER, CENTER - RADAR_RADIUS);
            ctx.lineTo(CENTER, CENTER + RADAR_RADIUS);
            ctx.moveTo(CENTER - RADAR_RADIUS, CENTER);
            ctx.lineTo(CENTER + RADAR_RADIUS, CENTER);
            ctx.stroke();
            ctx.beginPath();
            const diagonalOffset = RADAR_RADIUS * Math.cos(Math.PI / 4);
            ctx.moveTo(CENTER - diagonalOffset, CENTER - diagonalOffset);
            ctx.lineTo(CENTER + diagonalOffset, CENTER + diagonalOffset);
            ctx.moveTo(CENTER - diagonalOffset, CENTER + diagonalOffset);
            ctx.lineTo(CENTER + diagonalOffset, CENTER - diagonalOffset);
            ctx.stroke();
        }
        ctx.fillStyle = '#00ff00';
        ctx.font = '10px monospace';
        ctx.textAlign = 'center';
        for (let i = 1; i <= 4; i++) {
            const radius = (RADAR_RADIUS / 4) * i;
            const distance = (maxRange / 4) * i;
            const label = distance >= 1000 ? `${(distance / 1000).toFixed(1)}km` : `${distance}m`;
            ctx.fillText(label, CENTER + radius * 0.7, CENTER - radius * 0.7);
        }
    };
    const drawScanLine = (ctx) => {
        if (!isScanning)
            return;
        const angle = degToRad(scanAngle);
        const gradient = ctx.createLinearGradient(CENTER, CENTER, CENTER + RADAR_RADIUS * Math.cos(angle), CENTER + RADAR_RADIUS * Math.sin(angle));
        gradient.addColorStop(0, 'rgba(0, 255, 0, 0.8)');
        gradient.addColorStop(0.7, 'rgba(0, 255, 0, 0.3)');
        gradient.addColorStop(1, 'rgba(0, 255, 0, 0)');
        ctx.strokeStyle = gradient;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(CENTER, CENTER);
        ctx.lineTo(CENTER + RADAR_RADIUS * Math.cos(angle), CENTER + RADAR_RADIUS * Math.sin(angle));
        ctx.stroke();
        const sweepAngle = 45;
        const sweepGradient = ctx.createRadialGradient(CENTER, CENTER, 0, CENTER, CENTER, RADAR_RADIUS);
        sweepGradient.addColorStop(0, 'rgba(0, 255, 0, 0.1)');
        sweepGradient.addColorStop(1, 'rgba(0, 255, 0, 0)');
        ctx.fillStyle = sweepGradient;
        ctx.beginPath();
        ctx.moveTo(CENTER, CENTER);
        ctx.arc(CENTER, CENTER, RADAR_RADIUS, angle - degToRad(sweepAngle / 2), angle + degToRad(sweepAngle / 2));
        ctx.closePath();
        ctx.fill();
    };
    const drawTargets = (ctx) => {
        targets.forEach((target) => {
            const radius = distanceToRadius(target.distance);
            const angle = degToRad(target.bearing - 90);
            const x = CENTER + radius * Math.cos(angle);
            const y = CENTER + radius * Math.sin(angle);
            let color = '#ffffff';
            let size = 3;
            switch (target.type) {
                case 'geofence':
                    color = '#ffff00';
                    size = 4;
                    break;
                case 'user':
                    color = '#ff0000';
                    size = 5;
                    break;
                case 'poi':
                    color = '#00ffff';
                    size = 3;
                    break;
            }
            const targetAngle = (target.bearing - 90 + 360) % 360;
            const currentScanAngle = scanAngle % 360;
            const angleDiff = Math.abs(targetAngle - currentScanAngle);
            const isDetected = angleDiff < 10 || angleDiff > 350;
            if (isDetected && isScanning && !detectedTargets.has(target.id)) {
                setDetectedTargets(prev => new Set([...prev, target.id]));
                setPulseTargets(prev => new Set([...prev, target.id]));
                onTargetDetected?.(target);
                setTimeout(() => {
                    setPulseTargets(prev => {
                        const newSet = new Set(prev);
                        newSet.delete(target.id);
                        return newSet;
                    });
                }, 3000);
            }
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(x, y, size, 0, 2 * Math.PI);
            ctx.fill();
            if (target.strength > 0) {
                ctx.strokeStyle = color;
                ctx.lineWidth = 1;
                ctx.globalAlpha = target.strength * 0.5;
                ctx.beginPath();
                ctx.arc(x, y, size + 3, 0, 2 * Math.PI);
                ctx.stroke();
                ctx.globalAlpha = 1;
            }
            if (pulseTargets.has(target.id)) {
                const pulseRadius = size + 5 + Math.sin(Date.now() / 200) * 3;
                ctx.strokeStyle = color;
                ctx.lineWidth = 2;
                ctx.globalAlpha = 0.6;
                ctx.beginPath();
                ctx.arc(x, y, pulseRadius, 0, 2 * Math.PI);
                ctx.stroke();
                ctx.globalAlpha = 1;
            }
            if (detectedTargets.has(target.id)) {
                ctx.fillStyle = color;
                ctx.font = '8px monospace';
                ctx.textAlign = 'center';
                ctx.fillText(target.name, x, y - size - 8);
                if (target.reward) {
                    ctx.fillText(`+${target.reward}`, x, y + size + 12);
                }
            }
        });
    };
    const drawRadar = () => {
        const canvas = canvasRef.current;
        if (!canvas)
            return;
        const ctx = canvas.getContext('2d');
        if (!ctx)
            return;
        drawRadarBackground(ctx);
        drawTargets(ctx);
        drawScanLine(ctx);
    };
    (0, react_1.useEffect)(() => {
        if (!isScanning) {
            if (animationRef.current) {
                cancelAnimationFrame(animationRef.current);
            }
            return;
        }
        const animate = () => {
            setScanAngle(prev => (prev + 2 * scanSpeed) % 360);
            drawRadar();
            animationRef.current = requestAnimationFrame(animate);
        };
        animationRef.current = requestAnimationFrame(animate);
        return () => {
            if (animationRef.current) {
                cancelAnimationFrame(animationRef.current);
            }
        };
    }, [isScanning, scanSpeed]);
    (0, react_1.useEffect)(() => {
        drawRadar();
    }, [targets, maxRange, showGrid, scanAngle, detectedTargets, pulseTargets]);
    const resetDetection = () => {
        setDetectedTargets(new Set());
        setPulseTargets(new Set());
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: `relative bg-black rounded-lg overflow-hidden ${className}`, children: [(0, jsx_runtime_1.jsx)("canvas", { ref: canvasRef, width: RADAR_SIZE, height: RADAR_SIZE, className: "w-full h-full" }), (0, jsx_runtime_1.jsxs)("div", { className: "absolute top-2 right-2 flex flex-col space-y-1", children: [(0, jsx_runtime_1.jsxs)("div", { className: "bg-black bg-opacity-70 text-green-400 text-xs px-2 py-1 rounded", children: ["\u8303\u56F4: ", maxRange >= 1000 ? `${(maxRange / 1000).toFixed(1)}km` : `${maxRange}m`] }), (0, jsx_runtime_1.jsxs)("div", { className: "bg-black bg-opacity-70 text-green-400 text-xs px-2 py-1 rounded", children: ["\u76EE\u6807: ", detectedTargets.size, "/", targets.length] }), isScanning && ((0, jsx_runtime_1.jsxs)("div", { className: "bg-black bg-opacity-70 text-green-400 text-xs px-2 py-1 rounded flex items-center space-x-1", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Zap, { className: "h-3 w-3" }), (0, jsx_runtime_1.jsx)("span", { children: "\u626B\u63CF\u4E2D" })] }))] }), (0, jsx_runtime_1.jsx)("div", { className: "absolute bottom-2 right-2", children: (0, jsx_runtime_1.jsx)("button", { onClick: resetDetection, className: "bg-green-600 hover:bg-green-700 text-white text-xs px-2 py-1 rounded", title: "\u91CD\u7F6E\u68C0\u6D4B", children: (0, jsx_runtime_1.jsx)(lucide_react_1.Target, { className: "h-3 w-3" }) }) }), (0, jsx_runtime_1.jsxs)("div", { className: "absolute bottom-2 left-2 flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)("div", { className: `h-2 w-2 rounded-full ${isScanning ? 'bg-green-400 animate-pulse' : 'bg-gray-600'}` }), (0, jsx_runtime_1.jsx)("span", { className: "text-green-400 text-xs", children: isScanning ? '活跃' : '待机' })] })] }));
};
exports.default = RadarScanner;
//# sourceMappingURL=RadarScanner.js.map