import { File, Paths } from 'expo-file-system';
import { Platform } from 'react-native';
import { launchImageLibraryAsync } from 'expo-image-picker';
import { ImageManipulator, SaveFormat } from 'expo-image-manipulator';
import { MAX_AVATAR_LENGTH, validateAvatar } from './presentation';

export async function pickAvatar(): Promise<string | undefined> {
  const result = await launchImageLibraryAsync({ mediaTypes: ['images'], allowsEditing: true, aspect: [1, 1], quality: 1 });
  const asset = result.assets?.[0];
  if (result.canceled || !asset) return undefined;
  if (asset.fileSize && asset.fileSize > 20 * 1024 * 1024) throw new Error('Choose a photo smaller than 20 MB.');
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
        if (!output.base64) throw new Error('Could not read that photo.');
        const avatar = `data:image/jpeg;base64,${output.base64}`;
        if (avatar.length <= MAX_AVATAR_LENGTH) return validateAvatar(avatar);
      }
      throw new Error('Choose a simpler photo so it fits your avatar.');
    } finally { image.release(); }
  } finally {
    context.release();
    if (Platform.OS !== "web" && asset.uri.startsWith(Paths.cache.uri)) new File(asset.uri).delete();
  }
}
