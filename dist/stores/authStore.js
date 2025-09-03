"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuthStore = void 0;
const zustand_1 = require("zustand");
const middleware_1 = require("zustand/middleware");
const API_BASE_URL = process.env['REACT_APP_API_URL'] || 'http://localhost:3001/api';
exports.useAuthStore = (0, zustand_1.create)()((0, middleware_1.persist)((set, get) => ({
    user: null,
    token: null,
    isLoading: false,
    error: null,
    isAuthenticated: false,
    login: async (email, password) => {
        set({ isLoading: true, error: null });
        try {
            const response = await fetch(`${API_BASE_URL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || '登录失败');
            }
            const { user, token } = data.data;
            set({
                user,
                token,
                isAuthenticated: true,
                isLoading: false,
                error: null,
            });
            localStorage.setItem('auth_token', token);
        }
        catch (error) {
            set({
                error: error.message || '登录失败',
                isLoading: false,
                isAuthenticated: false,
            });
            throw error;
        }
    },
    register: async (email, password, username) => {
        set({ isLoading: true, error: null });
        try {
            const response = await fetch(`${API_BASE_URL}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password, username }),
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || '注册失败');
            }
            const { user, token } = data.data;
            set({
                user,
                token,
                isAuthenticated: true,
                isLoading: false,
                error: null,
            });
            localStorage.setItem('auth_token', token);
        }
        catch (error) {
            set({
                error: error.message || '注册失败',
                isLoading: false,
                isAuthenticated: false,
            });
            throw error;
        }
    },
    logout: () => {
        set({
            user: null,
            token: null,
            isAuthenticated: false,
            error: null,
        });
        localStorage.removeItem('auth_token');
    },
    checkAuth: async () => {
        const token = localStorage.getItem('auth_token');
        if (!token) {
            set({ isAuthenticated: false, user: null, token: null });
            return;
        }
        set({ isLoading: true });
        try {
            const response = await fetch(`${API_BASE_URL}/auth/me`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            if (!response.ok) {
                throw new Error('Token验证失败');
            }
            const data = await response.json();
            const user = data.data;
            set({
                user,
                token,
                isAuthenticated: true,
                isLoading: false,
                error: null,
            });
        }
        catch (error) {
            set({
                user: null,
                token: null,
                isAuthenticated: false,
                isLoading: false,
                error: error.message || '认证失败',
            });
            localStorage.removeItem('auth_token');
        }
    },
    updateProfile: async (data) => {
        const { token } = get();
        if (!token) {
            throw new Error('未登录');
        }
        set({ isLoading: true, error: null });
        try {
            const response = await fetch(`${API_BASE_URL}/auth/profile`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                },
                body: JSON.stringify(data),
            });
            const responseData = await response.json();
            if (!response.ok) {
                throw new Error(responseData.message || '更新失败');
            }
            const updatedUser = responseData.data;
            set({
                user: updatedUser,
                isLoading: false,
                error: null,
            });
        }
        catch (error) {
            set({
                error: error.message || '更新失败',
                isLoading: false,
            });
            throw error;
        }
    },
    refreshToken: async () => {
        const { token } = get();
        if (!token) {
            throw new Error('未登录');
        }
        try {
            const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || 'Token刷新失败');
            }
            const { token: newToken } = data.data;
            set({ token: newToken });
            localStorage.setItem('auth_token', newToken);
        }
        catch (error) {
            get().logout();
            throw error;
        }
    },
    setLoading: (loading) => {
        set({ isLoading: loading });
    },
    setError: (error) => {
        set({ error });
    },
    clearError: () => {
        set({ error: null });
    },
}), {
    name: 'auth-storage',
    partialize: (state) => ({
        token: state.token,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
    }),
}));
exports.default = exports.useAuthStore;
//# sourceMappingURL=authStore.js.map