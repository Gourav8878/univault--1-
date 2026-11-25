import { closeDatabase } from '../db/connection.ts';
import { seedDatabase } from '../db/seed.ts';

async function main(): Promise<void> {
  try {
    const result = await seedDatabase();
    console.log(
      result.seededNewData
        ? '[UniVault] Database and private storage seeded successfully.'
        : '[UniVault] Database already populated; verified idempotent baseline.'
    );
  } catch (error) {
    console.error('[UniVault] Seed failed:', error);
    process.exitCode = 1;
  } finally {
    closeDatabase();
  }
}

void main();
