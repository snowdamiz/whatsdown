import { File, Paths } from 'expo-file-system';

const databaseUri = new File(Paths.document, 'whatsdown.db').uri;

export const databasePath = decodeURIComponent(databaseUri.replace(/^file:\/\//, ''));
