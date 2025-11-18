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
    this.logStep('Rozpoczęcie szyfrowania szyfrem Vigenère\'a', plaintext, undefined, `Klucz: ${key}`);
    const result = this._process(plaintext, key, true);
    this.logStep('Zakończenie szyfrowania', plaintext, result);
    return result;
  }

  decrypt(ciphertext: string, key: string): string {
    this.logStep('Rozpoczęcie deszyfrowania szyfrem Vigenère\'a', ciphertext, undefined, `Klucz: ${key}`);
    const result = this._process(ciphertext, key, false);
    this.logStep('Zakończenie deszyfrowania', ciphertext, result);
    return result;
  }

  private _process(text: string, key: string, encrypt: boolean): string {
    let result = '';
    let keyIndex = 0;
    
    // Normalizuj klucz do wielkich liter
    const normalizedKey = key.toUpperCase();
    this.logStep(
      'Przygotowanie klucza',
      key,
      normalizedKey,
      `Długość klucza: ${normalizedKey.length}`
    );
    
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      
      if (char >= 'A' && char <= 'Z') {
        // Wielka litera
        const textCode = char.charCodeAt(0) - 65;
        const keyChar = normalizedKey.charAt(keyIndex % normalizedKey.length);
        const keyCode = keyChar.charCodeAt(0) - 65;
        
        let resultCode;
        if (encrypt) {
          resultCode = (textCode + keyCode) % 26;
        } else {
          resultCode = (textCode - keyCode + 26) % 26;
        }
        
        const resultChar = String.fromCharCode(resultCode + 65);
        result += resultChar;
        
        if (i < 5 || i >= text.length - 5) {
          this.logStep(
            `Znak ${i + 1}: ${char} ${encrypt ? '+' : '-'} ${keyChar} = ${resultChar}`,
            char,
            resultChar,
            `${textCode} ${encrypt ? '+' : '-'} ${keyCode} = ${resultCode} (mod 26)`
          );
        }
        keyIndex++;
      }
      else if (char >= 'a' && char <= 'z') {
        // Mała litera
        const textCode = char.charCodeAt(0) - 97;
        const keyChar = normalizedKey.charAt(keyIndex % normalizedKey.length);
        const keyCode = keyChar.charCodeAt(0) - 65;
        
        let resultCode;
        if (encrypt) {
          resultCode = (textCode + keyCode) % 26;
        } else {
          resultCode = (textCode - keyCode + 26) % 26;
        }
        
        const resultChar = String.fromCharCode(resultCode + 97);
        result += resultChar;
        
        if (i < 5 || i >= text.length - 5) {
          this.logStep(
            `Znak ${i + 1}: ${char} ${encrypt ? '+' : '-'} ${keyChar} = ${resultChar}`,
            char,
            resultChar,
            `${textCode} ${encrypt ? '+' : '-'} ${keyCode} = ${resultCode} (mod 26)`
          );
        }
        keyIndex++;
      }
      else {
        // Nie-litera, przepisz bez zmian
        result += char;
        if (i < 5 || i >= text.length - 5) {
          this.logStep(`Znak ${i + 1}: ${char} (bez zmian)`, char, char, 'Znak specjalny - pomijany');
        }
      }
    }
    
    if (text.length > 10) {
      this.logStep('Pominięto szczegóły', undefined, undefined, `Przetworzono ${text.length - 10} znaków środkowych`);
    }
    
    return result;
  }
}
