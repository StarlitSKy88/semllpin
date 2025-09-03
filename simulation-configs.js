#!/usr/bin/env node

/**
 * SmellPin User Simulation Configuration Manager
 * 
 * This script provides predefined configurations for different testing scenarios
 * and allows easy management of simulation parameters.
 */

const SIMULATION_CONFIGS = {
  // Quick smoke test
  smoke: {
    name: 'Smoke Test',
    description: 'Quick validation with minimal users',
    config: {
      CONCURRENT_USERS: 5,
      TEST_DURATION_MINUTES: 2,
      MAX_ANNOTATIONS_PER_USER: 1,
      REWARD_CLAIM_PROBABILITY: 0.5,
      PAYMENT_SUCCESS_RATE: 1.0
    }
  },

  // Load testing
  load: {
    name: 'Load Test',
    description: 'Normal expected traffic simulation',
    config: {
      CONCURRENT_USERS: 25,
      TEST_DURATION_MINUTES: 5,
      MAX_ANNOTATIONS_PER_USER: 3,
      REWARD_CLAIM_PROBABILITY: 0.7,
      PAYMENT_SUCCESS_RATE: 0.95
    }
  },

  // Stress testing
  stress: {
    name: 'Stress Test',
    description: 'High traffic simulation to find breaking points',
    config: {
      CONCURRENT_USERS: 50,
      TEST_DURATION_MINUTES: 10,
      MAX_ANNOTATIONS_PER_USER: 5,
      REWARD_CLAIM_PROBABILITY: 0.8,
      PAYMENT_SUCCESS_RATE: 0.9
    }
  },

  // Peak traffic simulation
  peak: {
    name: 'Peak Traffic Test',
    description: 'Simulate peak usage patterns',
    config: {
      CONCURRENT_USERS: 75,
      TEST_DURATION_MINUTES: 15,
      MAX_ANNOTATIONS_PER_USER: 4,
      REWARD_CLAIM_PROBABILITY: 0.6,
      PAYMENT_SUCCESS_RATE: 0.85
    }
  },

  // Endurance testing
  endurance: {
    name: 'Endurance Test',
    description: 'Long-running test for memory leaks and stability',
    config: {
      CONCURRENT_USERS: 20,
      TEST_DURATION_MINUTES: 30,
      MAX_ANNOTATIONS_PER_USER: 10,
      REWARD_CLAIM_PROBABILITY: 0.7,
      PAYMENT_SUCCESS_RATE: 0.9
    }
  },

  // Development testing
  dev: {
    name: 'Development Test',
    description: 'Quick development validation',
    config: {
      CONCURRENT_USERS: 3,
      TEST_DURATION_MINUTES: 1,
      MAX_ANNOTATIONS_PER_USER: 1,
      REWARD_CLAIM_PROBABILITY: 0.5,
      PAYMENT_SUCCESS_RATE: 1.0
    }
  }
};

/**
 * Run simulation with specified configuration
 */
async function runSimulationWithConfig(configName, apiUrl = 'http://localhost:3000') {
  const config = SIMULATION_CONFIGS[configName];
  
  if (!config) {
    console.error(`❌ Configuration '${configName}' not found.`);
    console.log('Available configurations:', Object.keys(SIMULATION_CONFIGS).join(', '));
    process.exit(1);
  }

  console.log(`🚀 Starting ${config.name}`);
  console.log(`📝 ${config.description}`);
  console.log(`👥 Users: ${config.config.CONCURRENT_USERS}`);
  console.log(`⏱️  Duration: ${config.config.TEST_DURATION_MINUTES} minutes`);
  console.log(`🌍 API URL: ${apiUrl}\n`);

  // Set environment variables
  process.env.API_URL = apiUrl;
  Object.entries(config.config).forEach(([key, value]) => {
    process.env[key] = value.toString();
  });

  // Import and run the simulation
  const { runComprehensiveUserSimulation } = require('./comprehensive-user-simulation.js');
  await runComprehensiveUserSimulation();
}

/**
 * Display available configurations
 */
function listConfigurations() {
  console.log('🎯 Available Simulation Configurations:\n');
  
  Object.entries(SIMULATION_CONFIGS).forEach(([name, config]) => {
    console.log(`📋 ${name.toUpperCase()}: ${config.name}`);
    console.log(`   ${config.description}`);
    console.log(`   Users: ${config.config.CONCURRENT_USERS}, Duration: ${config.config.TEST_DURATION_MINUTES}min`);
    console.log('');
  });
}

/**
 * Generate custom configuration
 */
function generateCustomConfig(users, duration, apiUrl) {
  const customConfig = {
    CONCURRENT_USERS: parseInt(users),
    TEST_DURATION_MINUTES: parseInt(duration),
    MAX_ANNOTATIONS_PER_USER: Math.max(1, Math.min(5, Math.floor(users / 10))),
    REWARD_CLAIM_PROBABILITY: 0.7,
    PAYMENT_SUCCESS_RATE: 0.9
  };

  console.log(`🎛️  Custom Configuration:`);
  console.log(`   Users: ${customConfig.CONCURRENT_USERS}`);
  console.log(`   Duration: ${customConfig.TEST_DURATION_MINUTES} minutes`);
  console.log(`   API URL: ${apiUrl}`);
  console.log('');

  return customConfig;
}

// Command line interface
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    listConfigurations();
    console.log('Usage:');
    console.log('  node simulation-configs.js <config-name> [api-url]');
    console.log('  node simulation-configs.js custom <users> <duration-minutes> [api-url]');
    console.log('');
    console.log('Examples:');
    console.log('  node simulation-configs.js smoke');
    console.log('  node simulation-configs.js load http://localhost:3000');
    console.log('  node simulation-configs.js custom 30 8');
    return;
  }

  const configName = args[0];
  const apiUrl = args[args.length - 1].startsWith('http') ? args[args.length - 1] : 'http://localhost:3000';

  if (configName === 'custom') {
    if (args.length < 3) {
      console.error('❌ Custom configuration requires users and duration parameters');
      console.log('Usage: node simulation-configs.js custom <users> <duration-minutes> [api-url]');
      process.exit(1);
    }

    const users = args[1];
    const duration = args[2];
    const customConfig = generateCustomConfig(users, duration, apiUrl);
    
    // Set environment variables
    process.env.API_URL = apiUrl;
    Object.entries(customConfig).forEach(([key, value]) => {
      process.env[key] = value.toString();
    });

    console.log('🚀 Starting custom simulation...\n');
    const { runComprehensiveUserSimulation } = require('./comprehensive-user-simulation.js');
    await runComprehensiveUserSimulation();
  } else {
    await runSimulationWithConfig(configName, apiUrl);
  }
}

// Export configurations for use in other modules
module.exports = {
  SIMULATION_CONFIGS,
  runSimulationWithConfig,
  listConfigurations,
  generateCustomConfig
};

// Run if called directly
if (require.main === module) {
  main().catch(error => {
    console.error('💥 Configuration manager error:', error);
    process.exit(1);
  });
}