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
    this.logStep('Rozpoczęcie szyfrowania szyfrem Cezara', plaintext, undefined, `Przesunięcie: ${shift}`);
    const result = this._process(plaintext, shift);
    this.logStep('Zakończenie szyfrowania', plaintext, result);
    return result;
  }

  decrypt(ciphertext: string, key: string): string {
    const shift = parseInt(key);
    this.logStep('Rozpoczęcie deszyfrowania szyfrem Cezara', ciphertext, undefined, `Przesunięcie: ${shift}`);
    const result = this._process(ciphertext, -shift);
    this.logStep('Zakończenie deszyfrowania', ciphertext, result);
    return result;
  }

  private _process(text: string, shift: number): string {
    let result = '';
    
    this.logStep('Przetwarzanie tekstu', text, undefined, `Przesunięcie: ${shift > 0 ? '+' : ''}${shift}`);
    
    for (let i = 0; i < text.length; i++) {
      let char = text[i];
      
      if (char >= 'A' && char <= 'Z') {
        let code = char.charCodeAt(0) - 65;
        let newCode = (code + shift + 26) % 26;
        let newChar = String.fromCharCode(newCode + 65);
        result += newChar;
        
        if (i < 5 || i >= text.length - 5) { // Loguj pierwsze i ostatnie 5 znaków
          this.logStep(
            `Znak ${i + 1}: ${char} → ${newChar}`,
            char,
            newChar,
            `Kod: ${code} → ${newCode}`
          );
        }
      }
      else if (char >= 'a' && char <= 'z') {
        let code = char.charCodeAt(0) - 97;
        let newCode = (code + shift + 26) % 26;
        let newChar = String.fromCharCode(newCode + 97);
        result += newChar;
        
        if (i < 5 || i >= text.length - 5) {
          this.logStep(
            `Znak ${i + 1}: ${char} → ${newChar}`,
            char,
            newChar,
            `Kod: ${code} → ${newCode}`
          );
        }
      }
      else {
        result += char;
        if (i < 5 || i >= text.length - 5) {
          this.logStep(`Znak ${i + 1}: ${char} (bez zmian)`, char, char, 'Znak specjalny');
        }
      }
    }
    
    if (text.length > 10) {
      this.logStep('Pominięto szczegóły', undefined, undefined, `Przetworzono ${text.length - 10} znaków środkowych`);
    }
    
    return result;
  }
}
