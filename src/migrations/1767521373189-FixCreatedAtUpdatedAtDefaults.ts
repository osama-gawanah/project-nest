import { MigrationInterface, QueryRunner } from 'typeorm';

export class FixCreatedAtUpdatedAtDefaults1767521373189 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`users\`
      MODIFY COLUMN \`createdAt\` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
    `);
    await queryRunner.query(`
      ALTER TABLE \`users\`
      MODIFY COLUMN \`updatedAt\` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`users\`
      MODIFY COLUMN \`createdAt\` datetime NOT NULL
    `);
    await queryRunner.query(`
      ALTER TABLE \`users\`
      MODIFY COLUMN \`updatedAt\` datetime NOT NULL
    `);
  }
}

