import WebSocketService from './websocketService';

// 全局WebSocket服务实例
let websocketServiceInstance: WebSocketService | null = null;

/**
 * 设置全局WebSocket服务实例
 * @param service WebSocket服务实例
 */
export function setWebSocketService(service: WebSocketService): void {
  websocketServiceInstance = service;
}

/**
 * 获取全局WebSocket服务实例
 * @returns WebSocket服务实例
 * @throws Error 如果服务未初始化
 */
export function getWebSocketService(): WebSocketService {
  if (!websocketServiceInstance) {
    throw new Error('WebSocket服务未初始化');
  }
  return websocketServiceInstance;
}

/**
 * 检查WebSocket服务是否已初始化
 * @returns 是否已初始化
 */
export function isWebSocketServiceInitialized(): boolean {
  return websocketServiceInstance !== null;
}

/**
 * 清理WebSocket服务实例
 */
export function clearWebSocketService(): void {
  websocketServiceInstance = null;
}