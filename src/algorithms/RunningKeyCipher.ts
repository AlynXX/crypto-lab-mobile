// ============================================================================
// IMPLEMENTACJA: Szyfr z kluczem bieżącym (Running Key Cipher)
// ============================================================================

import CryptographicAlgorithm from './CryptographicAlgorithm';
import { LoremIpsum } from 'lorem-ipsum';

export default class RunningKeyCipher extends CryptographicAlgorithm {
  constructor() {
    super(
      'Szyfr z kluczem bieżącym',
      'Szyfr podobny do Vigenère\'a, ale używający klucza o długości tekstu',
      'Szyfry klasyczne'
    );
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    if (!key || key.trim().length === 0) {
      return { valid: false, error: 'Klucz nie może być pusty' };
    }
    
    // Sprawdź czy klucz zawiera tylko litery
    const hasOnlyLetters = /^[a-zA-Z\s]+$/.test(key);
    if (!hasOnlyLetters) {
      return { valid: false, error: 'Klucz może zawierać tylko litery i spacje (A-Z, a-z)' };
    }
    
    // Policz tylko litery w kluczu
    const keyLettersCount = key.replace(/[^a-zA-Z]/g, '').length;
    if (keyLettersCount < 5) {
      return { 
        valid: false, 
        error: 'Klucz musi zawierać co najmniej 5 liter (może zawierać spacje)' 
      };
    }
    
    return { valid: true };
  }

  getKeyRequirements(): string {
    return 'Tekst (np. fragment książki) - klucz powinien być długi, zawierać tylko litery';
  }

  /**
   * Generuje klucz o długości tekstu z lorem ipsum
   */
  private generateKey(length: number): string {
    const lorem = new LoremIpsum({
      wordsPerSentence: { min: 5, max: 15 },
      sentencesPerParagraph: { min: 3, max: 7 }
    });
    let key = '';
    while (key.replace(/[^a-zA-Z]/g, '').length < length) {
      key += lorem.generateSentences(1) + ' ';
    }
    // Skróć do odpowiedniej liczby liter
    let onlyLetters = key.replace(/[^a-zA-Z]/g, '');
    onlyLetters = onlyLetters.substring(0, length);
    return onlyLetters;
  }

  encrypt(plaintext: string, _key?: string): string {
    // Generuj klucz automatycznie
    const key = this.generateKey(plaintext.replace(/[^a-zA-Z]/g, '').length);
    const ciphertext = this._process(plaintext, key, true);
    // Zwróć klucz i zaszyfrowany tekst w formacie: <klucz>::<zaszyfrowany_tekst>
    return `${key}::${ciphertext}`;
  }

  decrypt(ciphertext: string, _key?: string): string {
    // Oczekujemy formatu: <klucz>::<zaszyfrowany_tekst>
    const parts = ciphertext.split('::');
    if (parts.length !== 2) {
      throw new Error('Nieprawidłowy format zaszyfrowanego tekstu. Brak klucza.');
    }
    const key = parts[0];
    const encrypted = parts[1];
    return this._process(encrypted, key, false);
  }

  private _process(text: string, key: string, encrypt: boolean): string {
    let result = '';
    let keyIndex = 0;
    
    // Normalizuj klucz - usuń wszystko oprócz liter i zamień na wielkie
    const normalizedKey = key.replace(/[^a-zA-Z]/g, '').toUpperCase();
    
    if (normalizedKey.length === 0) {
      throw new Error('Klucz musi zawierać co najmniej jedną literę');
    }
    
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      
      if (char >= 'A' && char <= 'Z') {
        // Wielka litera
        if (keyIndex >= normalizedKey.length) {
          // Jeśli klucz jest krótszy niż tekst, wyświetl ostrzeżenie
          // ale kontynuuj używając klucza cyklicznie
          const textCode = char.charCodeAt(0) - 65;
          const keyCode = normalizedKey.charCodeAt(keyIndex % normalizedKey.length) - 65;
          
          let resultCode;
          if (encrypt) {
            resultCode = (textCode + keyCode) % 26;
          } else {
            resultCode = (textCode - keyCode + 26) % 26;
          }
          
          result += String.fromCharCode(resultCode + 65);
        } else {
          const textCode = char.charCodeAt(0) - 65;
          const keyCode = normalizedKey.charCodeAt(keyIndex) - 65;
          
          let resultCode;
          if (encrypt) {
            resultCode = (textCode + keyCode) % 26;
          } else {
            resultCode = (textCode - keyCode + 26) % 26;
          }
          
          result += String.fromCharCode(resultCode + 65);
        }
        keyIndex++;
      }
      else if (char >= 'a' && char <= 'z') {
        // Mała litera
        if (keyIndex >= normalizedKey.length) {
          const textCode = char.charCodeAt(0) - 97;
          const keyCode = normalizedKey.charCodeAt(keyIndex % normalizedKey.length) - 65;
          
          let resultCode;
          if (encrypt) {
            resultCode = (textCode + keyCode) % 26;
          } else {
            resultCode = (textCode - keyCode + 26) % 26;
          }
          
          result += String.fromCharCode(resultCode + 97);
        } else {
          const textCode = char.charCodeAt(0) - 97;
          const keyCode = normalizedKey.charCodeAt(keyIndex) - 65;
          
          let resultCode;
          if (encrypt) {
            resultCode = (textCode + keyCode) % 26;
          } else {
            resultCode = (textCode - keyCode + 26) % 26;
          }
          
          result += String.fromCharCode(resultCode + 97);
        }
        keyIndex++;
      }
      else {
        // Nie-litera, przepisz bez zmian
        result += char;
      }
    }
    
    return result;
  }
  
  /**
   * Pomocnicza metoda do sprawdzenia czy klucz jest wystarczająco długi
   */
  isKeySufficient(plaintext: string, key: string): boolean {
    const plaintextLetters = plaintext.replace(/[^a-zA-Z]/g, '').length;
    const keyLetters = key.replace(/[^a-zA-Z]/g, '').length;
    return keyLetters >= plaintextLetters;
  }
}
