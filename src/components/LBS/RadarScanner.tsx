/**
 * 雷达扫描动画组件
 * 提供雷达扫描视觉效果，用于LBS位置检测
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

import React, { useRef, useEffect, useState } from 'react';
import { Zap, Target } from 'lucide-react';

interface RadarTarget {
  id: string;
  name: string;
  distance: number; // 距离（米）
  bearing: number; // 方位角（度）
  type: 'geofence' | 'user' | 'poi';
  strength: number; // 信号强度 0-1
  reward?: number;
}

interface RadarScannerProps {
  isScanning: boolean;
  targets: RadarTarget[];
  maxRange: number; // 最大扫描范围（米）
  className?: string;
  onTargetDetected?: (target: RadarTarget) => void;
  showGrid?: boolean;
  scanSpeed?: number; // 扫描速度倍数
}

const RadarScanner: React.FC<RadarScannerProps> = ({
  isScanning,
  targets,
  maxRange = 1000,
  className = '',
  onTargetDetected,
  showGrid = true,
  scanSpeed = 1
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>(0);
  const [scanAngle, setScanAngle] = useState(0);
  const [detectedTargets, setDetectedTargets] = useState<Set<string>>(new Set());
  const [pulseTargets, setPulseTargets] = useState<Set<string>>(new Set());

  const RADAR_SIZE = 300;
  const CENTER = RADAR_SIZE / 2;
  const RADAR_RADIUS = CENTER - 20;

  // 角度转弧度
  const degToRad = (degrees: number) => (degrees * Math.PI) / 180;

  // 距离转换为雷达半径
  const distanceToRadius = (distance: number) => {
    return Math.min((distance / maxRange) * RADAR_RADIUS, RADAR_RADIUS);
  };

  // 绘制雷达背景
  const drawRadarBackground = (ctx: CanvasRenderingContext2D) => {
    // 清空画布
    ctx.clearRect(0, 0, RADAR_SIZE, RADAR_SIZE);
    
    // 设置雷达背景色
    ctx.fillStyle = '#0a0a0a';
    ctx.fillRect(0, 0, RADAR_SIZE, RADAR_SIZE);
    
    // 绘制雷达圆圈
    ctx.strokeStyle = '#00ff00';
    ctx.lineWidth = 1;
    
    // 外圆
    ctx.beginPath();
    ctx.arc(CENTER, CENTER, RADAR_RADIUS, 0, 2 * Math.PI);
    ctx.stroke();
    
    if (showGrid) {
      // 内圆（距离圈）
      for (let i = 1; i < 4; i++) {
        ctx.beginPath();
        ctx.arc(CENTER, CENTER, (RADAR_RADIUS / 4) * i, 0, 2 * Math.PI);
        ctx.stroke();
      }
      
      // 十字线
      ctx.beginPath();
      ctx.moveTo(CENTER, CENTER - RADAR_RADIUS);
      ctx.lineTo(CENTER, CENTER + RADAR_RADIUS);
      ctx.moveTo(CENTER - RADAR_RADIUS, CENTER);
      ctx.lineTo(CENTER + RADAR_RADIUS, CENTER);
      ctx.stroke();
      
      // 对角线
      ctx.beginPath();
      const diagonalOffset = RADAR_RADIUS * Math.cos(Math.PI / 4);
      ctx.moveTo(CENTER - diagonalOffset, CENTER - diagonalOffset);
      ctx.lineTo(CENTER + diagonalOffset, CENTER + diagonalOffset);
      ctx.moveTo(CENTER - diagonalOffset, CENTER + diagonalOffset);
      ctx.lineTo(CENTER + diagonalOffset, CENTER - diagonalOffset);
      ctx.stroke();
    }
    
    // 绘制距离标签
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

  // 绘制扫描线
  const drawScanLine = (ctx: CanvasRenderingContext2D) => {
    if (!isScanning) return;
    
    const angle = degToRad(scanAngle);
    
    // 扫描线渐变
    const gradient = ctx.createLinearGradient(
      CENTER,
      CENTER,
      CENTER + RADAR_RADIUS * Math.cos(angle),
      CENTER + RADAR_RADIUS * Math.sin(angle)
    );
    gradient.addColorStop(0, 'rgba(0, 255, 0, 0.8)');
    gradient.addColorStop(0.7, 'rgba(0, 255, 0, 0.3)');
    gradient.addColorStop(1, 'rgba(0, 255, 0, 0)');
    
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(CENTER, CENTER);
    ctx.lineTo(
      CENTER + RADAR_RADIUS * Math.cos(angle),
      CENTER + RADAR_RADIUS * Math.sin(angle)
    );
    ctx.stroke();
    
    // 扫描扇形区域
    const sweepAngle = 45; // 扫描扇形角度
    const sweepGradient = ctx.createRadialGradient(CENTER, CENTER, 0, CENTER, CENTER, RADAR_RADIUS);
    sweepGradient.addColorStop(0, 'rgba(0, 255, 0, 0.1)');
    sweepGradient.addColorStop(1, 'rgba(0, 255, 0, 0)');
    
    ctx.fillStyle = sweepGradient;
    ctx.beginPath();
    ctx.moveTo(CENTER, CENTER);
    ctx.arc(
      CENTER,
      CENTER,
      RADAR_RADIUS,
      angle - degToRad(sweepAngle / 2),
      angle + degToRad(sweepAngle / 2)
    );
    ctx.closePath();
    ctx.fill();
  };

  // 绘制目标点
  const drawTargets = (ctx: CanvasRenderingContext2D) => {
    targets.forEach((target) => {
      const radius = distanceToRadius(target.distance);
      const angle = degToRad(target.bearing - 90); // 调整角度，使0度指向北
      
      const x = CENTER + radius * Math.cos(angle);
      const y = CENTER + radius * Math.sin(angle);
      
      // 根据目标类型设置颜色
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
      
      // 检查目标是否被扫描线检测到
      const targetAngle = (target.bearing - 90 + 360) % 360;
      const currentScanAngle = scanAngle % 360;
      const angleDiff = Math.abs(targetAngle - currentScanAngle);
      const isDetected = angleDiff < 10 || angleDiff > 350; // 10度检测范围
      
      if (isDetected && isScanning && !detectedTargets.has(target.id)) {
        setDetectedTargets(prev => new Set([...prev, target.id]));
        setPulseTargets(prev => new Set([...prev, target.id]));
        onTargetDetected?.(target);
        
        // 3秒后移除脉冲效果
        setTimeout(() => {
          setPulseTargets(prev => {
            const newSet = new Set(prev);
            newSet.delete(target.id);
            return newSet;
          });
        }, 3000);
      }
      
      // 绘制目标点
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(x, y, size, 0, 2 * Math.PI);
      ctx.fill();
      
      // 绘制目标强度环
      if (target.strength > 0) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 1;
        ctx.globalAlpha = target.strength * 0.5;
        ctx.beginPath();
        ctx.arc(x, y, size + 3, 0, 2 * Math.PI);
        ctx.stroke();
        ctx.globalAlpha = 1;
      }
      
      // 绘制脉冲效果
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
      
      // 绘制目标信息（仅对检测到的目标）
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

  // 绘制雷达
  const drawRadar = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    drawRadarBackground(ctx);
    drawTargets(ctx);
    drawScanLine(ctx);
  };

  // 动画循环
  useEffect(() => {
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

  // 重绘雷达（当目标或配置改变时）
  useEffect(() => {
    drawRadar();
  }, [targets, maxRange, showGrid, scanAngle, detectedTargets, pulseTargets]);

  // 重置检测状态
  const resetDetection = () => {
    setDetectedTargets(new Set());
    setPulseTargets(new Set());
  };

  return (
    <div className={`relative bg-black rounded-lg overflow-hidden ${className}`}>
      {/* 雷达画布 */}
      <canvas
        ref={canvasRef}
        width={RADAR_SIZE}
        height={RADAR_SIZE}
        className="w-full h-full"
      />
      
      {/* 控制面板 */}
      <div className="absolute top-2 right-2 flex flex-col space-y-1">
        <div className="bg-black bg-opacity-70 text-green-400 text-xs px-2 py-1 rounded">
          范围: {maxRange >= 1000 ? `${(maxRange / 1000).toFixed(1)}km` : `${maxRange}m`}
        </div>
        <div className="bg-black bg-opacity-70 text-green-400 text-xs px-2 py-1 rounded">
          目标: {detectedTargets.size}/{targets.length}
        </div>
        {isScanning && (
          <div className="bg-black bg-opacity-70 text-green-400 text-xs px-2 py-1 rounded flex items-center space-x-1">
            <Zap className="h-3 w-3" />
            <span>扫描中</span>
          </div>
        )}
      </div>
      
      {/* 重置按钮 */}
      <div className="absolute bottom-2 right-2">
        <button
          onClick={resetDetection}
          className="bg-green-600 hover:bg-green-700 text-white text-xs px-2 py-1 rounded"
          title="重置检测"
        >
          <Target className="h-3 w-3" />
        </button>
      </div>
      
      {/* 状态指示器 */}
      <div className="absolute bottom-2 left-2 flex items-center space-x-2">
        <div className={`h-2 w-2 rounded-full ${
          isScanning ? 'bg-green-400 animate-pulse' : 'bg-gray-600'
        }`} />
        <span className="text-green-400 text-xs">
          {isScanning ? '活跃' : '待机'}
        </span>
      </div>
    </div>
  );
};

export default RadarScanner;