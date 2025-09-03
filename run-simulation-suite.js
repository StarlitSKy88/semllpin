#!/usr/bin/env node

/**
 * SmellPin Simulation Suite Runner
 * 
 * This script orchestrates the complete simulation testing process:
 * 1. Checks backend API availability
 * 2. Starts backend if needed
 * 3. Runs the specified simulation configuration
 * 4. Generates comprehensive reports
 */

const { spawn } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const API_URL = process.env.API_URL || 'http://localhost:3000';
const BACKEND_START_TIMEOUT = 30000; // 30 seconds

/**
 * Check if the API is available
 */
async function checkAPIHealth(maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      console.log(`🔍 Checking API health (attempt ${i + 1}/${maxRetries})...`);
      const response = await axios.get(`${API_URL}/health`, { 
        timeout: 5000,
        validateStatus: () => true 
      });
      
      if (response.status === 200) {
        console.log('✅ API is healthy and ready');
        return true;
      }
    } catch (error) {
      console.log(`❌ API check failed: ${error.message}`);
      if (i < maxRetries - 1) {
        console.log('⏳ Waiting 3 seconds before retry...');
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
    }
  }
  
  return false;
}

/**
 * Start the backend server
 */
async function startBackend() {
  return new Promise((resolve, reject) => {
    console.log('🚀 Starting SmellPin backend server...');
    
    // Check if package.json exists
    if (!fs.existsSync('./package.json')) {
      reject(new Error('package.json not found. Please run from the project root directory.'));
      return;
    }

    // Start the backend using npm run dev
    const backendProcess = spawn('npm', ['run', 'dev'], {
      stdio: 'pipe',
      env: { ...process.env, NODE_ENV: 'development' }
    });

    let started = false;
    const timeout = setTimeout(() => {
      if (!started) {
        backendProcess.kill();
        reject(new Error('Backend startup timeout'));
      }
    }, BACKEND_START_TIMEOUT);

    // Monitor backend output
    backendProcess.stdout.on('data', (data) => {
      const output = data.toString();
      process.stdout.write(`[Backend] ${output}`);
      
      // Look for startup indicators
      if (output.includes('Server running') || 
          output.includes('listening on') || 
          output.includes('port 3000')) {
        if (!started) {
          started = true;
          clearTimeout(timeout);
          console.log('✅ Backend server started successfully');
          resolve(backendProcess);
        }
      }
    });

    backendProcess.stderr.on('data', (data) => {
      process.stderr.write(`[Backend Error] ${data}`);
    });

    backendProcess.on('error', (error) => {
      clearTimeout(timeout);
      reject(new Error(`Failed to start backend: ${error.message}`));
    });

    backendProcess.on('exit', (code) => {
      if (!started) {
        clearTimeout(timeout);
        reject(new Error(`Backend exited with code ${code} before startup`));
      }
    });
  });
}

/**
 * Run database migrations if needed
 */
async function runMigrations() {
  return new Promise((resolve) => {
    console.log('🗃️  Running database migrations...');
    
    const migrateProcess = spawn('npm', ['run', 'migrate'], {
      stdio: 'pipe'
    });

    migrateProcess.stdout.on('data', (data) => {
      process.stdout.write(`[Migration] ${data}`);
    });

    migrateProcess.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ Database migrations completed');
      } else {
        console.log('⚠️  Migration warning (this might be expected)');
      }
      resolve(code === 0);
    });
  });
}

/**
 * Create test reports directory
 */
function ensureReportsDirectory() {
  const reportsDir = path.join(__dirname, 'test-reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
    console.log('📁 Created test-reports directory');
  }
}

/**
 * Run the simulation with specified configuration
 */
async function runSimulation(configName = 'load', customUsers = null, customDuration = null) {
  console.log('\n🎯 Starting SmellPin User Simulation...\n');
  
  const { runSimulationWithConfig, generateCustomConfig } = require('./simulation-configs.js');
  
  if (customUsers && customDuration) {
    // Custom configuration
    const customConfig = generateCustomConfig(customUsers, customDuration, API_URL);
    
    // Set environment variables
    process.env.API_URL = API_URL;
    Object.entries(customConfig).forEach(([key, value]) => {
      process.env[key] = value.toString();
    });

    const { runComprehensiveUserSimulation } = require('./comprehensive-user-simulation.js');
    return await runComprehensiveUserSimulation();
  } else {
    // Predefined configuration
    return await runSimulationWithConfig(configName, API_URL);
  }
}

/**
 * Display usage information
 */
function showUsage() {
  console.log('🎯 SmellPin Simulation Suite Runner');
  console.log('==================================\n');
  console.log('Usage:');
  console.log('  node run-simulation-suite.js [config] [options]\n');
  console.log('Predefined Configurations:');
  console.log('  dev      - Quick development test (3 users, 1 minute)');
  console.log('  smoke    - Smoke test (5 users, 2 minutes)');
  console.log('  load     - Load test (25 users, 5 minutes) [DEFAULT]');
  console.log('  stress   - Stress test (50 users, 10 minutes)');
  console.log('  peak     - Peak traffic (75 users, 15 minutes)');
  console.log('  endurance - Endurance test (20 users, 30 minutes)\n');
  console.log('Custom Configuration:');
  console.log('  --custom <users> <duration>  - Custom simulation parameters\n');
  console.log('Options:');
  console.log('  --no-backend   - Skip backend startup (assume already running)');
  console.log('  --api-url URL  - Specify API URL (default: http://localhost:3000)');
  console.log('  --help, -h     - Show this help message\n');
  console.log('Examples:');
  console.log('  node run-simulation-suite.js                    # Default load test');
  console.log('  node run-simulation-suite.js smoke              # Quick smoke test');
  console.log('  node run-simulation-suite.js --custom 30 8      # 30 users, 8 minutes');
  console.log('  node run-simulation-suite.js load --no-backend  # Load test, backend running');
}

/**
 * Parse command line arguments
 */
function parseArguments() {
  const args = process.argv.slice(2);
  const options = {
    config: 'load',
    startBackend: true,
    apiUrl: 'http://localhost:3000',
    customUsers: null,
    customDuration: null,
    showHelp: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '--help':
      case '-h':
        options.showHelp = true;
        break;
      case '--no-backend':
        options.startBackend = false;
        break;
      case '--api-url':
        options.apiUrl = args[++i];
        break;
      case '--custom':
        options.customUsers = parseInt(args[++i]);
        options.customDuration = parseInt(args[++i]);
        break;
      default:
        if (!arg.startsWith('--') && 
            ['dev', 'smoke', 'load', 'stress', 'peak', 'endurance'].includes(arg)) {
          options.config = arg;
        }
        break;
    }
  }

  // Update API URL
  if (options.apiUrl !== 'http://localhost:3000') {
    process.env.API_URL = options.apiUrl;
  }

  return options;
}

/**
 * Main execution function
 */
async function main() {
  const options = parseArguments();
  
  if (options.showHelp) {
    showUsage();
    return;
  }

  console.log('🌍 SmellPin Comprehensive Testing Suite');
  console.log('=======================================\n');

  let backendProcess = null;

  try {
    // Ensure reports directory exists
    ensureReportsDirectory();

    // Check if API is available
    const apiAvailable = await checkAPIHealth(1);
    
    if (!apiAvailable && options.startBackend) {
      console.log('🚀 API not available, starting backend server...\n');
      
      // Run migrations first
      await runMigrations();
      
      // Start backend
      backendProcess = await startBackend();
      
      // Wait for backend to be ready
      console.log('⏳ Waiting for backend to be ready...');
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      // Verify backend is ready
      const isReady = await checkAPIHealth(3);
      if (!isReady) {
        throw new Error('Backend started but API health check still fails');
      }
    } else if (!apiAvailable) {
      throw new Error('API not available and --no-backend specified. Please start the backend manually.');
    }

    console.log('\n' + '='.repeat(50));
    console.log('🎬 SIMULATION EXECUTION STARTING');
    console.log('='.repeat(50) + '\n');

    // Run simulation
    if (options.customUsers && options.customDuration) {
      await runSimulation('custom', options.customUsers, options.customDuration);
    } else {
      await runSimulation(options.config);
    }

    console.log('\n' + '='.repeat(50));
    console.log('🎉 SIMULATION COMPLETED SUCCESSFULLY');
    console.log('='.repeat(50));
    
    // List generated reports
    const reportsDir = path.join(__dirname, 'test-reports');
    if (fs.existsSync(reportsDir)) {
      const reports = fs.readdirSync(reportsDir)
        .filter(file => file.includes('simulation-report'))
        .sort()
        .reverse() // Most recent first
        .slice(0, 5); // Show last 5 reports

      if (reports.length > 0) {
        console.log('\n📊 Generated Reports:');
        reports.forEach(report => {
          console.log(`   📄 ${report}`);
        });
        console.log(`\n📁 Reports location: ${reportsDir}`);
      }
    }

  } catch (error) {
    console.error('\n💥 Simulation suite failed:', error.message);
    console.error('Please check the error details above and try again.\n');
    
    if (error.stack) {
      console.error('Stack trace:', error.stack);
    }
    
    process.exit(1);
  } finally {
    // Cleanup: Kill backend if we started it
    if (backendProcess) {
      console.log('\n🛑 Stopping backend server...');
      backendProcess.kill('SIGTERM');
      
      // Give it 5 seconds to gracefully shutdown
      setTimeout(() => {
        if (!backendProcess.killed) {
          backendProcess.kill('SIGKILL');
        }
      }, 5000);
    }
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Simulation interrupted by user');
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Simulation terminated');
  process.exit(1);
});

// Run if called directly
if (require.main === module) {
  main().catch(error => {
    console.error('💥 Suite runner error:', error);
    process.exit(1);
  });
}

module.exports = {
  checkAPIHealth,
  startBackend,
  runSimulation,
  main
};