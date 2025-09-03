import '@testing-library/jest-dom'

// Mock IntersectionObserver
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
}

// Mock ResizeObserver
global.ResizeObserver = class ResizeObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
}

// Mock matchMedia
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
})

// Mock geolocation
Object.defineProperty(navigator, 'geolocation', {
  writable: true,
  value: {
    getCurrentPosition: jest.fn().mockImplementation((success) => {
      success({
        coords: {
          latitude: 39.9042,
          longitude: 116.4074,
          accuracy: 10
        }
      })
    }),
    watchPosition: jest.fn().mockImplementation((success) => {
      success({
        coords: {
          latitude: 39.9042,
          longitude: 116.4074,
          accuracy: 10
        }
      })
      return 1
    }),
    clearWatch: jest.fn()
  }
})

// Mock Leaflet
jest.mock('leaflet', () => ({
  Icon: {
    Default: {
      prototype: {
        _getIconUrl: undefined
      },
      mergeOptions: jest.fn()
    }
  },
  divIcon: jest.fn(() => ({
    options: {},
    createIcon: jest.fn(),
    createShadow: jest.fn()
  })),
  Map: jest.fn(() => ({
    setView: jest.fn(),
    addLayer: jest.fn(),
    removeLayer: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    remove: jest.fn()
  })),
  tileLayer: jest.fn(() => ({
    addTo: jest.fn(),
    remove: jest.fn()
  })),
  marker: jest.fn(() => ({
    addTo: jest.fn(),
    remove: jest.fn(),
    bindPopup: jest.fn(),
    openPopup: jest.fn(),
    closePopup: jest.fn(),
    setLatLng: jest.fn(),
    getLatLng: jest.fn()
  }))
}))

// Mock react-leaflet
jest.mock('react-leaflet', () => ({
  MapContainer: ({ children, ...props }) => <div data-testid="map-container" {...props}>{children}</div>,
  TileLayer: (props) => <div data-testid="tile-layer" {...props} />,
  Marker: ({ children, ...props }) => <div data-testid="marker" {...props}>{children}</div>,
  Popup: ({ children, ...props }) => <div data-testid="popup" {...props}>{children}</div>,
  useMap: () => ({
    on: jest.fn(),
    off: jest.fn(),
    setView: jest.fn(),
    getZoom: jest.fn(() => 13),
    getCenter: jest.fn(() => ({ lat: 39.9042, lng: 116.4074 }))
  })
}))

// Mock next/router
jest.mock('next/router', () => ({
  useRouter: () => ({
    push: jest.fn(),
    replace: jest.fn(),
    prefetch: jest.fn(),
    query: {},
    pathname: '/',
    asPath: '/',
  })
}))

// Mock framer-motion
jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }) => <div {...props}>{children}</div>,
    button: ({ children, ...props }) => <button {...props}>{children}</button>,
    span: ({ children, ...props }) => <span {...props}>{children}</span>
  },
  AnimatePresence: ({ children }) => <>{children}</>,
  useSpring: () => ({ set: jest.fn() }),
  useTransform: () => 0,
  useMotionValue: () => ({ set: jest.fn(), get: jest.fn(() => 0) })
}))

// Mock axios
jest.mock('axios', () => ({
  create: jest.fn(() => ({
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    interceptors: {
      request: { use: jest.fn() },
      response: { use: jest.fn() }
    }
  })),
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn()
}))

// Set up console suppression for cleaner test output
const originalError = console.error
const originalWarn = console.warn

beforeAll(() => {
  console.error = (...args) => {
    if (
      typeof args[0] === 'string' &&
      (args[0].includes('Warning: ReactDOM.render') ||
       args[0].includes('Warning: render') ||
       args[0].includes('act(...)'))
    ) {
      return
    }
    originalError.call(console, ...args)
  }

  console.warn = (...args) => {
    if (
      typeof args[0] === 'string' &&
      (args[0].includes('componentWillReceiveProps') ||
       args[0].includes('componentWillUpdate'))
    ) {
      return
    }
    originalWarn.call(console, ...args)
  }
})

afterAll(() => {
  console.error = originalError
  console.warn = originalWarn
})