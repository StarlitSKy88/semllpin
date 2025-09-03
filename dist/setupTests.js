"use strict";
var _a, _b;
Object.defineProperty(exports, "__esModule", { value: true });
require("@testing-library/jest-dom");
global.IntersectionObserver = class IntersectionObserver {
    constructor() { }
    observe() {
        return null;
    }
    disconnect() {
        return null;
    }
    unobserve() {
        return null;
    }
};
global.ResizeObserver = class ResizeObserver {
    constructor() { }
    observe() {
        return null;
    }
    disconnect() {
        return null;
    }
    unobserve() {
        return null;
    }
};
Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: jest.fn().mockImplementation(query => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
    })),
});
let locationMocked = false;
try {
    if (!window.__locationMocked) {
        delete window.location;
        Object.defineProperty(window, 'location', {
            value: {
                href: 'http://localhost:3000',
                origin: 'http://localhost:3000',
                protocol: 'http:',
                host: 'localhost:3000',
                hostname: 'localhost',
                port: '3000',
                pathname: '/',
                search: '',
                hash: '',
                assign: jest.fn(),
                replace: jest.fn(),
                reload: jest.fn(),
            },
            writable: true,
            configurable: true,
        });
        window.__locationMocked = true;
        locationMocked = true;
    }
}
catch (e) {
}
const originalError = console.error;
beforeAll(() => {
    console.error = (...args) => {
        if (typeof args[0] === 'string' &&
            args[0].includes('Warning: ReactDOM.render is deprecated')) {
            return;
        }
        originalError.call(console, ...args);
    };
});
afterAll(() => {
    console.error = originalError;
});
global.fetch = jest.fn(() => Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    blob: () => Promise.resolve(new Blob()),
}));
const localStorageMock = (() => {
    let store = {};
    return {
        getItem: (key) => store[key] || null,
        setItem: (key, value) => {
            store[key] = value;
        },
        removeItem: (key) => {
            delete store[key];
        },
        clear: () => {
            store = {};
        },
    };
})();
Object.defineProperty(window, 'localStorage', {
    value: localStorageMock,
});
Object.defineProperty(window, 'sessionStorage', {
    value: localStorageMock,
});
Object.defineProperty(URL, 'createObjectURL', {
    value: jest.fn(() => 'mocked-url'),
});
Object.defineProperty(URL, 'revokeObjectURL', {
    value: jest.fn(),
});
global.FileReader = (_a = class FileReader {
        constructor() {
            this.result = null;
            this.error = null;
            this.readyState = 0;
            this.onload = null;
            this.onerror = null;
            this.onabort = null;
            this.onloadstart = null;
            this.onloadend = null;
            this.onprogress = null;
            this.addEventListener = jest.fn();
            this.removeEventListener = jest.fn();
            this.dispatchEvent = jest.fn();
            this.readAsDataURL = jest.fn(function () {
                this.result = 'data:image/jpeg;base64,mock-data';
                if (this.onload) {
                    this.onload({});
                }
            });
            this.readAsText = jest.fn(function () {
                this.result = 'mock text content';
                if (this.onload) {
                    this.onload({});
                }
            });
            this.readAsArrayBuffer = jest.fn(function () {
                this.result = new ArrayBuffer(8);
                if (this.onload) {
                    this.onload({});
                }
            });
            this.abort = jest.fn();
        }
    },
    _a.EMPTY = 0,
    _a.LOADING = 1,
    _a.DONE = 2,
    _a);
global.Image = class Image {
    constructor() {
        this.src = '';
        this.alt = '';
        this.width = 0;
        this.height = 0;
        this.onload = null;
        this.onerror = null;
        setTimeout(() => {
            if (this.onload) {
                this.onload({});
            }
        }, 0);
    }
};
Object.defineProperty(navigator, 'geolocation', {
    value: {
        getCurrentPosition: jest.fn((success) => {
            success({
                coords: {
                    latitude: 40.7128,
                    longitude: -74.0060,
                    accuracy: 10,
                    altitude: null,
                    altitudeAccuracy: null,
                    heading: null,
                    speed: null,
                },
                timestamp: Date.now(),
            });
        }),
        watchPosition: jest.fn(),
        clearWatch: jest.fn(),
    },
    writable: true,
});
Object.defineProperty(window, 'Notification', {
    value: (_b = class Notification {
            constructor(_title, _options) {
                this.close = jest.fn();
            }
        },
        _b.permission = 'granted',
        _b.requestPermission = jest.fn(() => Promise.resolve('granted')),
        _b),
    writable: true,
});
afterEach(() => {
    jest.clearAllMocks();
    localStorageMock.clear();
});
//# sourceMappingURL=setupTests.js.map