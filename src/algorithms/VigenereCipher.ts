// ============================================================================
// IMPLEMENTACJA: Szyfr Vigenère'a (manualna implementacja)
// ============================================================================

import CryptographicAlgorithm from './CryptographicAlgorithm';

export default class VigenereCipher extends CryptographicAlgorithm {
  constructor() {
    super(
      'Szyfr Vigenère\'a',
      'Szyfr polialfabetyczny używający słowa kluczowego do szyfrowania',
      'Szyfry klasyczne'
    );
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    if (!key || key.trim().length === 0) {
      return { valid: false, error: 'Klucz nie może być pusty' };
    }
    
    // Sprawdź czy klucz zawiera tylko litery
    const hasOnlyLetters = /^[a-zA-Z]+$/.test(key);
    if (!hasOnlyLetters) {
      return { valid: false, error: 'Klucz może zawierać tylko litery (A-Z, a-z)' };
    }
    
    return { valid: true };
  }

  getKeyRequirements(): string {
    return 'Słowo lub fraza składająca się tylko z liter (A-Z)';
  }

  encrypt(plaintext: string, key: string): string {
    return this._process(plaintext, key, true);
  }

  decrypt(ciphertext: string, key: string): string {
    return this._process(ciphertext, key, false);
  }

  private _process(text: string, key: string, encrypt: boolean): string {
    let result = '';
    let keyIndex = 0;
    
    // Normalizuj klucz do wielkich liter
    const normalizedKey = key.toUpperCase();
    
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      
      if (char >= 'A' && char <= 'Z') {
        // Wielka litera
        const textCode = char.charCodeAt(0) - 65;
        const keyCode = normalizedKey.charCodeAt(keyIndex % normalizedKey.length) - 65;
        
        let resultCode;
        if (encrypt) {
          resultCode = (textCode + keyCode) % 26;
        } else {
          resultCode = (textCode - keyCode + 26) % 26;
        }
        
        result += String.fromCharCode(resultCode + 65);
        keyIndex++;
      }
      else if (char >= 'a' && char <= 'z') {
        // Mała litera
        const textCode = char.charCodeAt(0) - 97;
        const keyCode = normalizedKey.charCodeAt(keyIndex % normalizedKey.length) - 65;
        
        let resultCode;
        if (encrypt) {
          resultCode = (textCode + keyCode) % 26;
        } else {
          resultCode = (textCode - keyCode + 26) % 26;
        }
        
        result += String.fromCharCode(resultCode + 97);
        keyIndex++;
      }
      else {
        // Nie-litera, przepisz bez zmian
        result += char;
      }
    }
    
    return result;
  }
}
