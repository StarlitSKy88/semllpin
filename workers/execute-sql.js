require('dotenv').config({ path: '.dev.vars' });
const { neon } = require('@neondatabase/serverless');
const fs = require('fs');

async function executeSQLScript() {
  try {
    const sql = neon(process.env.DATABASE_URL);
    const sqlScript = fs.readFileSync('create-tables-neon.sql', 'utf8');
    
    console.log('Executing SQL script...');
    
    // Split the script into individual statements
    const statements = sqlScript
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt.length > 0 && !stmt.startsWith('--'));
    
    for (let i = 0; i < statements.length; i++) {
      const statement = statements[i];
      if (statement.trim()) {
        try {
          console.log(`Executing statement ${i + 1}/${statements.length}...`);
          const result = await sql`${sql.unsafe(statement)}`;
          console.log(`Statement ${i + 1} executed successfully`);
        } catch (error) {
          console.error(`Error in statement ${i + 1}:`, error.message);
          // Continue with next statement
        }
      }
    }
    
    console.log('SQL script execution completed');
    
    // Verify the table structure
    console.log('\nVerifying annotations table structure...');
    const tableStructure = await sql`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'annotations' 
      ORDER BY ordinal_position
    `;
    
    console.table(tableStructure);
    
  } catch (error) {
    console.error('Error:', error);
  }
}

executeSQLScript();