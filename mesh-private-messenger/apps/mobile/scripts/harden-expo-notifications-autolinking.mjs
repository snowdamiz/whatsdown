#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const EXPECTED_VERSION = '57.0.8';
const APPLE_TOKEN_MODULE = 'PushTokenModule';
const ANDROID_TOKEN_MODULE = 'expo.modules.notifications.tokens.PushTokenModule';
const UPSTREAM_CONFIG = {
  platforms: ['apple', 'android'],
  apple: {
    modules: [
      'BackgroundModule',
      'BadgeModule',
      'CategoriesModule',
      'EmitterModule',
      'HandlerModule',
      'PermissionsModule',
      'PresentationModule',
      APPLE_TOKEN_MODULE,
      'SchedulerModule',
      'ServerRegistrationModule',
    ],
    appDelegateSubscribers: ['NotificationsAppDelegateSubscriber'],
  },
  android: {
    modules: [
      'expo.modules.notifications.badge.BadgeModule',
      'expo.modules.notifications.notifications.background.ExpoBackgroundNotificationTasksModule',
      'expo.modules.notifications.notifications.categories.ExpoNotificationCategoriesModule',
      'expo.modules.notifications.notifications.channels.NotificationChannelGroupManagerModule',
      'expo.modules.notifications.notifications.channels.NotificationChannelManagerModule',
      'expo.modules.notifications.notifications.emitting.NotificationsEmitter',
      'expo.modules.notifications.notifications.handling.NotificationsHandler',
      'expo.modules.notifications.permissions.NotificationPermissionsModule',
      'expo.modules.notifications.notifications.presentation.ExpoNotificationPresentationModule',
      'expo.modules.notifications.notifications.scheduling.NotificationScheduler',
      'expo.modules.notifications.serverregistration.ServerRegistrationModule',
      ANDROID_TOKEN_MODULE,
      'expo.modules.notifications.topics.TopicSubscriptionModule',
      'expo.modules.notifications.notifications.channels.AndroidXNotificationsChannelsProvider',
    ],
    publication: {
      groupId: 'host.exp.exponent',
      artifactId: 'expo.modules.notifications',
      version: EXPECTED_VERSION,
      repository: 'local-maven-repo',
    },
  },
};
const HARDENED_CONFIG = structuredClone(UPSTREAM_CONFIG);
HARDENED_CONFIG.apple.modules = HARDENED_CONFIG.apple.modules.filter(
  (moduleName) => moduleName !== APPLE_TOKEN_MODULE,
);
HARDENED_CONFIG.android.modules = HARDENED_CONFIG.android.modules.filter(
  (moduleName) => moduleName !== ANDROID_TOKEN_MODULE,
);

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`could not read ${path}: ${error.message}`);
  }
}

export async function hardenExpoNotifications(packageDirectory, { check = false } = {}) {
  const packagePath = resolve(packageDirectory, 'package.json');
  const configPath = resolve(packageDirectory, 'expo-module.config.json');
  const packageJson = await readJson(packagePath);

  if (packageJson.name !== 'expo-notifications' || packageJson.version !== EXPECTED_VERSION) {
    throw new Error(
      `expected expo-notifications ${EXPECTED_VERSION}, found ${packageJson.name ?? 'unknown'} ${packageJson.version ?? 'unknown'}`,
    );
  }

  const config = await readJson(configPath);
  const isUpstream = isDeepStrictEqual(config, UPSTREAM_CONFIG);
  const isHardened = isDeepStrictEqual(config, HARDENED_CONFIG);

  if (!isUpstream && !isHardened) {
    throw new Error(`unexpected expo-notifications ${EXPECTED_VERSION} autolinking config shape`);
  }
  if (check && !isHardened) {
    throw new Error('expo-notifications raw push-token modules are still autolinked');
  }
  if (!check && isUpstream) {
    await writeFile(configPath, `${JSON.stringify(HARDENED_CONFIG, null, 2)}\n`, 'utf8');
    return true;
  }
  return false;
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) {
    console.error('usage: harden-expo-notifications-autolinking.mjs [--check]');
    process.exitCode = 2;
  } else {
    const check = args[0] === '--check';
    const packageDirectory = resolve(dirname(scriptPath), '../node_modules/expo-notifications');
    hardenExpoNotifications(packageDirectory, { check })
      .then((changed) => {
        console.log(
          changed
            ? 'Removed expo-notifications raw push-token autolinking.'
            : 'expo-notifications raw push-token autolinking is disabled.',
        );
      })
      .catch((error) => {
        console.error(`expo-notifications hardening failed: ${error.message}`);
        process.exitCode = 1;
      });
  }
}
