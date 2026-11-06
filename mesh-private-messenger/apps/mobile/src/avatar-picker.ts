import { protectedHandle, protectedMetadata } from './app-lock';
import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { File, Paths } from 'expo-file-system';
import { Platform } from 'react-native';
import { launchImageLibraryAsync } from 'expo-image-picker';
import { ImageManipulator, SaveFormat } from 'expo-image-manipulator';
import { t } from './i18n';
import { MAX_AVATAR_LENGTH, validateAvatar } from './presentation';
export function createAvatarServices(deps: Pick<ScopedClient, 'runPrivate' | 'protectedFile'>) {
  async function pickAvatar(): Promise<string | undefined> {
    const context = { version: 1, purpose: 'avatar' };
    let row = protectedMetadata(await deps.protectedFile('pendingChoice', context), ['choiceId']);
    if (row.choiceId === undefined) {
      row = protectedMetadata(await deps.protectedFile('chooseSource', context), ['choiceId', 'cancelled']);
      if (row.cancelled === true) return undefined;
    }
    // Native imports/crops/encodes only under this new explicit action's epoch.
    // It never forwards a source URI to a stale ImageManipulator operation.
    const result = protectedMetadata(await deps.protectedFile('importAvatar', { ...context, choiceId: protectedHandle(row.choiceId) }), ['avatar', 'cancelled']);
    if (result.cancelled !== undefined) {
      if (result.cancelled !== true || result.avatar !== undefined) throw Error('invalid_avatar');
      return undefined;
    }
    if (typeof result.avatar !== 'string' || result.avatar.length > MAX_AVATAR_LENGTH) throw Error('invalid_avatar');
    return validateAvatar(result.avatar);
  }
  return Object.freeze({ pickAvatar: () => deps.runPrivate(pickAvatar) });
}
async function pickDesktopAvatar(): Promise<string | undefined> {
  const result = await launchImageLibraryAsync({ mediaTypes: ['images'], allowsEditing: true, aspect: [1, 1], quality: 1 });
  const asset = result.assets?.[0];
  if (result.canceled || !asset) return undefined;
  if (asset.fileSize && asset.fileSize > 20 * 1024 * 1024) throw new Error(t('Choose a photo smaller than 20 MB.'));
  const side = Math.min(asset.width, asset.height);
  const context = ImageManipulator.manipulate(asset.uri);
  try {
    context.crop({ originX: Math.floor((asset.width - side) / 2), originY: Math.floor((asset.height - side) / 2), width: side, height: side });
    context.resize({ width: 160, height: 160 });
    const image = await context.renderAsync();
    try {
      for (const compress of [0.7, 0.45, 0.2]) {
        const output = await image.saveAsync({ format: SaveFormat.JPEG, compress, base64: true });
        if (Platform.OS !== "web" && output.uri.startsWith(Paths.cache.uri)) new File(output.uri).delete();
        if (!output.base64) throw new Error(t('Could not read that photo.'));
        const avatar = `data:image/jpeg;base64,${output.base64}`;
        if (avatar.length <= MAX_AVATAR_LENGTH) return validateAvatar(avatar);
      }
      throw new Error(t('Choose a simpler photo so it fits your avatar.'));
    } finally { image.release(); }
  } finally {
    context.release();
    if (Platform.OS !== "web" && asset.uri.startsWith(Paths.cache.uri)) new File(asset.uri).delete();
  }
}
export const pickAvatar: ReturnType<typeof createAvatarServices>['pickAvatar'] = (...args) => {
  if (!isLegacyDesktopBridge) throw Error('scoped_client_required');
  return pickDesktopAvatar(...args);
};
