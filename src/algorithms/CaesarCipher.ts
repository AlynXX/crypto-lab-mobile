// ============================================================================
// IMPLEMENTACJA: Szyfr Cezara (manualna implementacja)
// ============================================================================

import CryptographicAlgorithm from './CryptographicAlgorithm';

export default class CaesarCipher extends CryptographicAlgorithm {
  constructor() {
    super(
      'Szyfr Cezara',
      'Klasyczny szyfr substytucyjny przesuwający litery o stałą wartość',
      'Szyfry klasyczne'
    );
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    const shift = parseInt(key);
    if (isNaN(shift)) {
      return { valid: false, error: 'Klucz musi być liczbą całkowitą' };
    }
    if (shift < 1 || shift > 25) {
      return { valid: false, error: 'Klucz musi być w zakresie 1-25' };
    }
    return { valid: true };
  }

  getKeyRequirements(): string {
    return 'Liczba całkowita od 1 do 25 (przesunięcie w alfabecie)';
  }

  encrypt(plaintext: string, key: string): string {
    const shift = parseInt(key);
    return this._process(plaintext, shift);
  }

  decrypt(ciphertext: string, key: string): string {
    const shift = parseInt(key);
    return this._process(ciphertext, -shift);
  }

  private _process(text: string, shift: number): string {
    let result = '';
    
    for (let i = 0; i < text.length; i++) {
      let char = text[i];
      
      if (char >= 'A' && char <= 'Z') {
        let code = char.charCodeAt(0) - 65;
        code = (code + shift + 26) % 26;
        result += String.fromCharCode(code + 65);
      }
      else if (char >= 'a' && char <= 'z') {
        let code = char.charCodeAt(0) - 97;
        code = (code + shift + 26) % 26;
        result += String.fromCharCode(code + 97);
      }
      else {
        result += char;
      }
    }
    
    return result;
  }
}
