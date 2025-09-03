import '@testing-library/jest-dom';

// Mock IntersectionObserver
(global as any).IntersectionObserver = class IntersectionObserver {
  constructor() {}
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

// Mock ResizeObserver
(global as any).ResizeObserver = class ResizeObserver {
  constructor() {}
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

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(), // deprecated
    removeListener: jest.fn(), // deprecated
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

// Mock window.location (only if not already mocked)
let locationMocked = false;
try {
  if (!(window as any).__locationMocked) {
    delete (window as any).location;
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
    (window as any).__locationMocked = true;
    locationMocked = true;
  }
} catch (e) {
  // If redefining fails, location is already mocked, skip
}

// Mock console methods to reduce noise in tests
const originalError = console.error;
beforeAll(() => {
  console.error = (...args: any[]) => {
    if (
      typeof args[0] === 'string' &&
      args[0].includes('Warning: ReactDOM.render is deprecated')
    ) {
      return;
    }
    originalError.call(console, ...args);
  };
});

afterAll(() => {
  console.error = originalError;
});

// Mock fetch
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    blob: () => Promise.resolve(new Blob()),
  } as Response)
);

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value;
    },
    removeItem: (key: string) => {
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

// Mock sessionStorage
Object.defineProperty(window, 'sessionStorage', {
  value: localStorageMock,
});

// Mock URL.createObjectURL
Object.defineProperty(URL, 'createObjectURL', {
  value: jest.fn(() => 'mocked-url'),
});

Object.defineProperty(URL, 'revokeObjectURL', {
  value: jest.fn(),
});

// Mock FileReader
(global as any).FileReader = class FileReader {
  result: string | ArrayBuffer | null = null;
  error: DOMException | null = null;
  readyState: number = 0;
  
  onload: ((this: any, ev: any) => any) | null = null;
  onerror: ((this: any, ev: any) => any) | null = null;
  onabort: ((this: any, ev: any) => any) | null = null;
  onloadstart: ((this: any, ev: any) => any) | null = null;
  onloadend: ((this: any, ev: any) => any) | null = null;
  onprogress: ((this: any, ev: any) => any) | null = null;
  
  addEventListener = jest.fn();
  removeEventListener = jest.fn();
  dispatchEvent = jest.fn();
  
  readAsDataURL = jest.fn(function(this: any) {
    this.result = 'data:image/jpeg;base64,mock-data';
    if (this.onload) {
      this.onload({});
    }
  });
  
  readAsText = jest.fn(function(this: any) {
    this.result = 'mock text content';
    if (this.onload) {
      this.onload({});
    }
  });
  
  readAsArrayBuffer = jest.fn(function(this: any) {
    this.result = new ArrayBuffer(8);
    if (this.onload) {
      this.onload({});
    }
  });
  
  abort = jest.fn();
  
  static readonly EMPTY = 0;
  static readonly LOADING = 1;
  static readonly DONE = 2;
};

// Mock Image
(global as any).Image = class Image {
  src: string = '';
  alt: string = '';
  width: number = 0;
  height: number = 0;
  onload: ((this: any, ev: any) => any) | null = null;
  onerror: ((this: any, ev: any) => any) | null = null;
  
  constructor() {
    setTimeout(() => {
      if (this.onload) {
        this.onload({});
      }
    }, 0);
  }
};

// Mock navigator.geolocation
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

// Mock Notification API
Object.defineProperty(window, 'Notification', {
  value: class Notification {
    static permission = 'granted';
    static requestPermission = jest.fn(() => Promise.resolve('granted'));
    
    constructor(_title: string, _options?: NotificationOptions) {
      // Mock notification
    }
    
    close = jest.fn();
  },
  writable: true,
});

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
  localStorageMock.clear();
});