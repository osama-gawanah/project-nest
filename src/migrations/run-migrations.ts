import { Sequelize, DataTypes } from 'sequelize';
import { ConfigService } from '@nestjs/config';
import * as mysql2 from 'mysql2';
import * as fs from 'fs';
import * as path from 'path';

async function runMigrations() {
  const configService = new ConfigService();
  
  const database = configService.get<string>('DB_NAME') || 'your_database_name';
  const username = configService.get<string>('DB_USER') || 'root';
  const password = configService.get<string>('DB_PASSWORD') || '1234';
  const host = configService.get<string>('DB_HOST') || 'localhost';
  const port = parseInt(configService.get<string>('DB_PORT') || '3306', 10);

  const sequelize = new Sequelize({
    dialect: 'mysql',
    dialectModule: mysql2,
    host,
    port,
    username,
    password,
    database,
    logging: console.log,
  });

  try {
    await sequelize.authenticate();
    console.log('✓ Database connection established successfully.');

    // Get migration directory
    const migrationsDir = __dirname;
    const migrationFiles = fs
      .readdirSync(migrationsDir)
      .filter((file) => 
        file.endsWith('.ts') && 
        file !== 'run-migrations.ts' && 
        file.startsWith('20') // Migration files start with year
      )
      .sort();

    console.log(`Found ${migrationFiles.length} migration file(s)`);

    // Create SequelizeMeta table if it doesn't exist
    const queryInterface = sequelize.getQueryInterface();
    try {
      await queryInterface.createTable('SequelizeMeta', {
        name: {
          type: DataTypes.STRING(255),
          primaryKey: true,
        },
      });
      console.log('✓ Created SequelizeMeta table');
    } catch (error: any) {
      if (error.name === 'SequelizeDatabaseError' && error.message.includes('already exists')) {
        console.log('✓ SequelizeMeta table already exists');
      } else {
        throw error;
      }
    }

    // Get executed migrations
    const [executedMigrations] = await sequelize.query(
      "SELECT name FROM SequelizeMeta",
    ) as any[];
    const executedNames = executedMigrations.map((m: any) => m.name);

    // Run pending migrations
    let executedCount = 0;
    for (const file of migrationFiles) {
      if (executedNames.includes(file)) {
        console.log(`⊘ Skipping ${file} (already executed)`);
        continue;
      }

      console.log(`→ Running migration: ${file}`);
      const migrationPath = path.join(migrationsDir, file);
      
      // Use dynamic import for ES modules compatibility
      delete require.cache[require.resolve(migrationPath)];
      const migration = require(migrationPath);
      
      if (typeof migration.up === 'function') {
        await migration.up(queryInterface);
        
        // Record migration
        await sequelize.query(
          `INSERT INTO SequelizeMeta (name) VALUES ('${file}')`,
        );
        
        console.log(`✓ Completed: ${file}`);
        executedCount++;
      } else {
        console.error(`✗ Invalid migration: ${file} - missing 'up' function`);
      }
    }

    if (executedCount > 0) {
      console.log(`\n✓ Successfully executed ${executedCount} migration(s)!`);
    } else {
      console.log('\n✓ All migrations are up to date.');
    }
  } catch (error) {
    console.error('\n✗ Migration error:', error);
    throw error;
  } finally {
    await sequelize.close();
  }
}

runMigrations()
  .then(() => {
    console.log('\n✓ Migrations finished successfully');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n✗ Migration failed:', error);
    process.exit(1);
  });

