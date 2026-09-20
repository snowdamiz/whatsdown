const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { AndroidConfig, withAndroidManifest, withDangerousMod } = require('@expo/config-plugins');

// The message database and its journals must never leave the device through an
// OS backup. `allowBackup="false"` alone is not enough: from Android 12 it no
// longer stops device-to-device transfer, which only explicit extraction rules
// do. The pre-12 rules file covers API 30 and below.
const DOMAINS = ['root', 'file', 'database', 'sharedpref', 'external'];
const excludes = indent => DOMAINS.map(domain => `${indent}<exclude domain="${domain}" path="." />`).join('\n');

const dataExtractionRules = `<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
  <cloud-backup>
${excludes('    ')}
  </cloud-backup>
  <device-transfer>
${excludes('    ')}
  </device-transfer>
</data-extraction-rules>
`;

const fullBackupContent = `<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
${excludes('  ')}
</full-backup-content>
`;

function writeBackupRules(platformProjectRoot) {
  const directory = join(platformProjectRoot, 'app/src/main/res/xml');
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'morse_data_extraction_rules.xml'), dataExtractionRules);
  writeFileSync(join(directory, 'morse_full_backup_content.xml'), fullBackupContent);
}

function withDataProtection(config) {
  config = withAndroidManifest(config, current => {
    const application = AndroidConfig.Manifest.getMainApplicationOrThrow(current.modResults);
    application.$['android:allowBackup'] = 'false';
    application.$['android:dataExtractionRules'] = '@xml/morse_data_extraction_rules';
    application.$['android:fullBackupContent'] = '@xml/morse_full_backup_content';
    return current;
  });
  return withDangerousMod(config, ['android', current => {
    writeBackupRules(current.modRequest.platformProjectRoot);
    return current;
  }]);
}

module.exports = withDataProtection;
module.exports.dataExtractionRules = dataExtractionRules;
module.exports.fullBackupContent = fullBackupContent;
module.exports.writeBackupRules = writeBackupRules;
