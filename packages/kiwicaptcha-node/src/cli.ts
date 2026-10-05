#!/usr/bin/env node
/**
 * The kiwicaptcha-doctor CLI: validates the deployment configuration
 * from the four-setting quickstart. The secret comes from the
 * KIWI_SECRET environment variable; the store is addressed by DSN
 * (memory, sqlite://path, or redis://host:port with the optional peers
 * installed).
 */
import { exit } from 'node:process';
import { runDoctor, type DoctorCheck } from './doctor.js';
import { MemoryStore } from './stores/memory.js';

interface CliArgs {
  store?: string;
  secret?: string;
  rswModulus?: string;
  rswLambda?: string;
}

function parseArgs(argv: readonly string[]): CliArgs {
  const args: CliArgs = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--store' && i + 1 < argv.length) {
      args.store = argv[++i];
    } else if (arg === '--secret' && i + 1 < argv.length) {
      args.secret = argv[++i];
    } else if (arg === '--rsw-modulus' && i + 1 < argv.length) {
      args.rswModulus = argv[++i];
    } else if (arg === '--rsw-lambda' && i + 1 < argv.length) {
      args.rswLambda = argv[++i];
    } else if (arg === '--help' || arg === '-h') {
      printUsage();
      exit(0);
    }
  }
  return args;
}

function printUsage(): void {
  process.stdout.write(
    'kiwicaptcha-doctor: validate the KiwiCaptcha deployment\n' +
      '\n' +
      'Environment:\n' +
      '  KIWI_SECRET   the master secret (required, at least 32 bytes)\n' +
      '\n' +
      'Flags:\n' +
      "  --store DSN          memory (default) | sqlite://path | redis://host:port\n" +
      '  --rsw-modulus B64    the rsw trapdoor modulus (with --rsw-lambda)\n' +
      '  --rsw-lambda B64     the rsw trapdoor lambda\n' +
      '  -h, --help           this text\n',
  );
}

async function openStore(dsn: string | undefined): Promise<{ store: import('./store.js').StoreAdapter; close: () => Promise<void> }> {
  const value = dsn ?? 'memory';
  if (value === 'memory') {
    return { store: new MemoryStore(), close: async () => undefined };
  }
  if (value.startsWith('sqlite://')) {
    const path = value.slice('sqlite://'.length);
    const sqliteModule = await import('better-sqlite3');
    const Database = (sqliteModule as { default: new (path: string) => unknown }).default;
    const { SqliteStore } = await import('./stores/sqlite.js');
    const db = new Database(path) as import('./stores/sqlite.js').SqliteLike;
    return { store: new SqliteStore(db), close: async () => undefined };
  }
  if (value.startsWith('redis://') || value.startsWith('rediss://')) {
    const redisModule = (await import('ioredis')) as unknown as {
      default: new (url: string) => import('./stores/redis.js').RedisLike & { quit(): Promise<void> };
    };
    const client = new redisModule.default(value);
    const { RedisStore } = await import('./stores/redis.js');
    return { store: new RedisStore(client), close: async () => client.quit() };
  }
  throw new Error(`unsupported store DSN: ${value} (use memory, sqlite://path or redis://host:port)`);
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const secret = args.secret ?? process.env.KIWI_SECRET;
  if (secret === undefined || secret === '') {
    process.stderr.write('kiwicaptcha-doctor: set KIWI_SECRET (or pass --secret)\n');
    return 2;
  }
  let handle: { store: import('./store.js').StoreAdapter; close: () => Promise<void> };
  try {
    handle = await openStore(args.store);
  } catch (error) {
    process.stderr.write(`kiwicaptcha-doctor: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
  try {
    const report = await runDoctor({
      secret,
      store: handle.store,
      rsw:
        args.rswModulus !== undefined && args.rswLambda !== undefined
          ? { modulusN: args.rswModulus, lambda: args.rswLambda }
          : null,
    });
    for (const check of report.checks as readonly DoctorCheck[]) {
      process.stdout.write(`${check.ok ? 'ok' : 'FAIL'}  ${check.name}: ${check.detail}\n`);
    }
    process.stdout.write(report.ok ? 'doctor: deployment sound\n' : 'doctor: findings above\n');
    return report.ok ? 0 : 1;
  } finally {
    await handle.close();
  }
}

main()
  .then((code) => exit(code))
  .catch((error: unknown) => {
    process.stderr.write(`kiwicaptcha-doctor: ${error instanceof Error ? error.message : String(error)}\n`);
    exit(2);
  });
