const { Client } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'smellpin',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
};

// Migration tracking table
const createMigrationsTable = `
  CREATE TABLE IF NOT EXISTS migrations (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) UNIQUE NOT NULL,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
  );
`;

async function runMigrations() {
  const client = new Client(dbConfig);
  
  try {
    console.log('Connecting to database...');
    await client.connect();
    
    // Create migrations tracking table
    console.log('Creating migrations table...');
    await client.query(createMigrationsTable);
    
    // Get list of executed migrations
    const { rows: executedMigrations } = await client.query(
      'SELECT filename FROM migrations ORDER BY id'
    );
    const executedFiles = new Set(executedMigrations.map(row => row.filename));
    
    // Get list of migration files
    const migrationsDir = path.join(__dirname, '..', 'migrations');
    const migrationFiles = fs.readdirSync(migrationsDir)
      .filter(file => file.endsWith('.sql'))
      .sort();
    
    console.log(`Found ${migrationFiles.length} migration files`);
    
    // Run pending migrations
    for (const filename of migrationFiles) {
      if (executedFiles.has(filename)) {
        console.log(`Skipping ${filename} (already executed)`);
        continue;
      }
      
      console.log(`Running migration: ${filename}`);
      
      const filePath = path.join(migrationsDir, filename);
      const sql = fs.readFileSync(filePath, 'utf8');
      
      try {
        // Begin transaction
        await client.query('BEGIN');
        
        // Execute migration
        await client.query(sql);
        
        // Record migration as executed
        await client.query(
          'INSERT INTO migrations (filename) VALUES ($1)',
          [filename]
        );
        
        // Commit transaction
        await client.query('COMMIT');
        
        console.log(`✓ Migration ${filename} completed successfully`);
      } catch (error) {
        // Rollback transaction
        await client.query('ROLLBACK');
        console.error(`✗ Migration ${filename} failed:`, error.message);
        throw error;
      }
    }
    
    console.log('All migrations completed successfully!');
    
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  } finally {
    await client.end();
  }
}

// Run migrations if this script is executed directly
if (require.main === module) {
  runMigrations();
}

module.exports = { runMigrations };