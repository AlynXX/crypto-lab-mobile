import * as DocumentPicker from 'expo-document-picker';
import { Paths, File } from 'expo-file-system';
import * as Sharing from 'expo-sharing';

export const pickTextFile = async (): Promise<string | null> => {
  try {
    const result = await DocumentPicker.getDocumentAsync({
      type: 'text/plain',
      copyToCacheDirectory: true,
    });

    if (result.canceled) {
      return null;
    }

    const file = new File(result.assets[0].uri);
    const fileContent = await file.text();
    return fileContent;
  } catch (error) {
    console.error('Error picking file:', error);
    throw new Error('Błąd podczas wczytywania pliku');
  }
};

export const saveTextFile = async (content: string, filename: string): Promise<void> => {
  try {
    const file = new File(Paths.cache, filename);
    await file.write(content);
    
    if (await Sharing.isAvailableAsync()) {
      await Sharing.shareAsync(file.uri);
    } else {
      throw new Error('Sharing nie jest dostępny na tym urządzeniu');
    }
  } catch (error) {
    console.error('Error saving file:', error);
    throw new Error('Błąd podczas zapisywania pliku');
  }
};
