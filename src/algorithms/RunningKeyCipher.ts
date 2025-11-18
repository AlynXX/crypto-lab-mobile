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
    return 'Tekst (np. fragment książki) - użyto generatora lorem ipsum do stworzenia klucza';
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
    this.logStep('Rozpoczęcie szyfrowania z kluczem bieżącym', plaintext, undefined, 'Szyfr z kluczem bieżącym (Running Key Cipher) - rozszerzenie szyfru Vigenère\'a. Używa klucza o długości równej tekstowi. Każda litera tekstu jest dodawana (modulo 26) do odpowiedniej litery klucza.');
    
    const keyLength = plaintext.replace(/[^a-zA-Z]/g, '').length;
    this.logStep('Obliczanie długości klucza', plaintext, undefined, `Liczymy tylko litery w tekście (pomijamy spacje, znaki interpunkcyjne). Znaleziono: ${keyLength} liter. Klucz musi mieć dokładnie tę samą długość, aby każda litera miała swoją parę w kluczu.`);
    
    const key = this.generateKey(keyLength);
    this.logStep('Wygenerowano klucz losowy', undefined, key.substring(0, Math.min(100, key.length)) + (key.length > 100 ? '...' : ''), `Używamy generatora Lorem Ipsum do stworzenia losowego tekstu o długości ${key.length} liter. To symuluje użycie fragmentu książki lub długiego tekstu jako klucza. Klucz: "${key.substring(0, 30)}${key.length > 30 ? '...' : ''}"`);
    
    // Przykłady dla pierwszych 3 i ostatnich 2 znaków
    const plaintextLetters = plaintext.replace(/[^a-zA-Z]/g, '');
    if (plaintextLetters.length > 0) {
      const examplesCount = Math.min(3, plaintextLetters.length);
      for (let i = 0; i < examplesCount; i++) {
        const char = plaintextLetters[i];
        const keyChar = key[i];
        const charCode = char.toUpperCase().charCodeAt(0) - 65;
        const keyCode = keyChar.toUpperCase().charCodeAt(0) - 65;
        const resultCode = (charCode + keyCode) % 26;
        const resultChar = String.fromCharCode(resultCode + 65);
        
        this.logStep(
          `Przykład: Litera ${i + 1}`,
          `Tekst: '${char}' (pozycja ${charCode})`,
          `Wynik: '${resultChar}' (pozycja ${resultCode})`,
          `Klucz: '${keyChar}' (poz. ${keyCode}). Obliczenie: (${charCode} + ${keyCode}) mod 26 = ${resultCode}. Formuła: C = (P + K) mod 26, gdzie P=plaintext, K=key, C=ciphertext. Modulo 26 bo mamy 26 liter w alfabecie.`
        );
      }
      
      // Ostatnie 2 znaki
      if (plaintextLetters.length > 5) {
        this.logStep('Pominięto środkowe znaki', undefined, undefined, `Zaszyfrowano ${plaintextLetters.length - 5} znaków środkowych tym samym procesem (dodawanie modulo 26). Pokazano pierwsze 3 i ostatnie 2 dla zwięzłości.`);
        
        for (let i = Math.max(plaintextLetters.length - 2, 3); i < plaintextLetters.length; i++) {
          const char = plaintextLetters[i];
          const keyChar = key[i];
          const charCode = char.toUpperCase().charCodeAt(0) - 65;
          const keyCode = keyChar.toUpperCase().charCodeAt(0) - 65;
          const resultCode = (charCode + keyCode) % 26;
          const resultChar = String.fromCharCode(resultCode + 65);
          
          this.logStep(
            `Przykład: Litera ${i + 1} (${i === plaintextLetters.length - 1 ? 'ostatnia' : 'przedostatnia'})`,
            `Tekst: '${char}' (poz. ${charCode})`,
            `Wynik: '${resultChar}' (poz. ${resultCode})`,
            `Klucz: '${keyChar}' (poz. ${keyCode}). Obliczenie: (${charCode} + ${keyCode}) mod 26 = ${resultCode}`
          );
        }
      }
    }
    
    this.logStep('Szyfrowanie całego tekstu', plaintext, undefined, `Proces: Każda litera tekstu jest dodawana do odpowiadającej litery klucza (modulo 26). Znaki niebędące literami (spacje, cyfry, interpunkcja) pozostają niezmienione.`);
    
    const ciphertext = this._process(plaintext, key, true);
    
    this.logStep('Zaszyfrowany tekst', plaintext, ciphertext, `Wszystkie litery zostały zaszyfrowane. Długość tekstu: ${plaintext.length} znaków (${plaintextLetters.length} liter). Wynik zawiera te same znaki niealfabetyczne na tych samych pozycjach.`);
    
    // Zwróć klucz i zaszyfrowany tekst w formacie: <klucz>::<zaszyfrowany_tekst>
    const result = `${key}::${ciphertext}`;
    this.logStep('Zakończenie szyfrowania', plaintext, ciphertext, `Format wyniku: KLUCZ::SZYFROGRAM. Klucz musi być przekazany odbiorcy (bezpiecznym kanałem!), aby mógł odszyfować wiadomość. Bez klucza deszyfrowanie jest praktycznie niemożliwe. Klucz: ${key.length} znaków.`);
    return result;
  }

  decrypt(ciphertext: string, _key?: string): string {
    // Oczekujemy formatu: <klucz>::<zaszyfrowany_tekst>
    this.logStep('Rozpoczęcie deszyfrowania z kluczem bieżącym', ciphertext.substring(0, 100) + (ciphertext.length > 100 ? '...' : ''), undefined, 'Deszyfrowanie szyfru z kluczem bieżącym. Proces odwrotny do szyfrowania: od każdej litery szyfrogramu odejmujemy (modulo 26) odpowiadającą literę klucza.');
    
    const parts = ciphertext.split('::');
    if (parts.length !== 2) {
      this.logStep('Błąd formatu danych', ciphertext, undefined, 'Oczekiwano formatu: KLUCZ::SZYFROGRAM. Znak "::" oddziela klucz od zaszyfrowanej wiadomości. Sprawdź, czy dane zostały prawidłowo skopiowane.');
      throw new Error('Nieprawidłowy format zaszyfrowanego tekstu. Brak klucza.');
    }
    
    const key = parts[0];
    const encrypted = parts[1];
    
    this.logStep('Wyekstrahowano klucz', undefined, key.substring(0, Math.min(100, key.length)) + (key.length > 100 ? '...' : ''), `Klucz o długości ${key.length} znaków został pomyślnie wyodrębniony z szyfrogramu. Klucz: "${key.substring(0, 30)}${key.length > 30 ? '...' : ''}". Ten sam klucz był użyty przy szyfrowaniu.`);
    
    this.logStep('Wyekstrahowano szyfrogram', undefined, encrypted, `Zaszyfrowana wiadomość o długości ${encrypted.length} znaków. Liczba liter do odszyfrowania: ${encrypted.replace(/[^a-zA-Z]/g, '').length}. Teraz odejmiemy wartości klucza od każdej litery.`);
    
    // Przykłady dla pierwszych 3 i ostatnich 2 znaków
    const encryptedLetters = encrypted.replace(/[^a-zA-Z]/g, '');
    if (encryptedLetters.length > 0) {
      const examplesCount = Math.min(3, encryptedLetters.length);
      for (let i = 0; i < examplesCount; i++) {
        const char = encryptedLetters[i];
        const keyChar = key[i];
        const charCode = char.toUpperCase().charCodeAt(0) - 65;
        const keyCode = keyChar.toUpperCase().charCodeAt(0) - 65;
        const resultCode = (charCode - keyCode + 26) % 26;
        const resultChar = String.fromCharCode(resultCode + 65);
        
        this.logStep(
          `Przykład: Litera ${i + 1}`,
          `Szyfrogram: '${char}' (poz. ${charCode})`,
          `Oryginał: '${resultChar}' (poz. ${resultCode})`,
          `Klucz: '${keyChar}' (poz. ${keyCode}). Obliczenie: (${charCode} - ${keyCode} + 26) mod 26 = ${resultCode}. Formuła: P = (C - K + 26) mod 26, gdzie C=ciphertext, K=key, P=plaintext. +26 zapewnia, że wynik jest dodatni.`
        );
      }
      
      // Ostatnie 2 znaki
      if (encryptedLetters.length > 5) {
        this.logStep('Pominięto środkowe znaki', undefined, undefined, `Odszyfrowano ${encryptedLetters.length - 5} znaków środkowych tym samym procesem (odejmowanie modulo 26). Pokazano pierwsze 3 i ostatnie 2 dla przejrzystości logów.`);
        
        for (let i = Math.max(encryptedLetters.length - 2, 3); i < encryptedLetters.length; i++) {
          const char = encryptedLetters[i];
          const keyChar = key[i];
          const charCode = char.toUpperCase().charCodeAt(0) - 65;
          const keyCode = keyChar.toUpperCase().charCodeAt(0) - 65;
          const resultCode = (charCode - keyCode + 26) % 26;
          const resultChar = String.fromCharCode(resultCode + 65);
          
          this.logStep(
            `Przykład: Litera ${i + 1} (${i === encryptedLetters.length - 1 ? 'ostatnia' : 'przedostatnia'})`,
            `Szyfrogram: '${char}' (poz. ${charCode})`,
            `Oryginał: '${resultChar}' (poz. ${resultCode})`,
            `Klucz: '${keyChar}' (poz. ${keyCode}). Obliczenie: (${charCode} - ${keyCode} + 26) mod 26 = ${resultCode}`
          );
        }
      }
    }
    
    this.logStep('Deszyfrowanie całego tekstu', encrypted, undefined, `Proces: Od każdej litery szyfrogramu odejmujemy odpowiadającą literę klucza (modulo 26). Znaki niebędące literami są kopiowane bez zmian. Operacja odwrotna do szyfrowania.`);
    
    const result = this._process(encrypted, key, false);
    
    this.logStep('Zakończenie deszyfrowania', encrypted, result, `Wszystkie litery zostały pomyślnie odszyfrowane! Odzyskano oryginalny tekst o długości ${result.length} znaków (${result.replace(/[^a-zA-Z]/g, '').length} liter). Bez znajomości klucza deszyfrowanie byłoby praktycznie niemożliwe.`);
    
    return result;
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
