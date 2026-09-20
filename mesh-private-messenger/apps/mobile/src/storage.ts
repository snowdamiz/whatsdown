import { File, Paths } from 'expo-file-system';

const databaseUri = new File(Paths.document, 'morse.db').uri;

export const databasePath = decodeURIComponent(databaseUri.replace(/^file:\/\//, ''));
