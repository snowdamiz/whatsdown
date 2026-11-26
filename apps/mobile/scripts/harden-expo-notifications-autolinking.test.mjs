import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { hardenExpoNotifications } from './harden-expo-notifications-autolinking.mjs';

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const installedPackage = resolve(scriptsDirectory, '../node_modules/expo-notifications');

test('raw push-token autolinking is removed idempotently and drift fails closed', async () => {
  const temporaryDirectory = await mkdtemp(resolve(tmpdir(), 'morse-expo-notifications-'));
  const fixture = resolve(temporaryDirectory, 'expo-notifications');

  try {
    await mkdir(fixture);
    await Promise.all(
      ['package.json', 'expo-module.config.json'].map((fileName) =>
        copyFile(resolve(installedPackage, fileName), resolve(fixture, fileName)),
      ),
    );
    const packagePath = resolve(fixture, 'package.json');
    const configPath = resolve(fixture, 'expo-module.config.json');
    const config = JSON.parse(await readFile(configPath, 'utf8'));
    if (!config.apple.modules.includes('PushTokenModule')) {
      config.apple.modules.splice(config.apple.modules.indexOf('SchedulerModule'), 0, 'PushTokenModule');
    }
    const androidTokenModule = 'expo.modules.notifications.tokens.PushTokenModule';
    if (!config.android.modules.includes(androidTokenModule)) {
      config.android.modules.splice(
        config.android.modules.indexOf('expo.modules.notifications.topics.TopicSubscriptionModule'),
        0,
        androidTokenModule,
      );
    }
    await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`);

    await assert.rejects(
      hardenExpoNotifications(fixture, { check: true }),
      /raw push-token modules are still autolinked/,
    );
    assert.equal(await hardenExpoNotifications(fixture), true);
    assert.equal(await hardenExpoNotifications(fixture), false);
    await hardenExpoNotifications(fixture, { check: true });

    const hardened = JSON.parse(await readFile(configPath, 'utf8'));
    hardened.apple.modules.push('UnexpectedModule');
    await writeFile(configPath, `${JSON.stringify(hardened, null, 2)}\n`);
    await assert.rejects(hardenExpoNotifications(fixture), /unexpected .* config shape/);

    hardened.apple.modules.pop();
    await writeFile(configPath, `${JSON.stringify(hardened, null, 2)}\n`);
    const packageJson = JSON.parse(await readFile(packagePath, 'utf8'));
    packageJson.version = '57.0.16';
    await writeFile(packagePath, `${JSON.stringify(packageJson, null, 2)}\n`);
    await assert.rejects(hardenExpoNotifications(fixture), /expected expo-notifications 57\.0\.15/);
  } finally {
    await rm(temporaryDirectory, { recursive: true });
  }
});
