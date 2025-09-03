// Import the TypeScript source file
const Server = require('../../src/server.ts').default;

// Create a server instance for testing
const serverInstance = new Server();

// Export the Express app for testing
module.exports = serverInstance.getApp();