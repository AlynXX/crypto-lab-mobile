// ============================================================================
// Podpis Elektroniczny (Digital Signature) - RSA-based
// ============================================================================
// Implementacja schematu podpisu cyfrowego opartego na RSA
// Pozwala na podpisywanie i weryfikację autentyczności dokumentów

import CryptographicAlgorithm from './CryptographicAlgorithm';
import SHA256Hash from './SHA256Hash';

export interface KeyPair {
  publicKey: { n: bigint; e: bigint };
  privateKey: { n: bigint; d: bigint };
}

export default class DigitalSignature extends CryptographicAlgorithm {
  private sha256: SHA256Hash;
  private keyPair: KeyPair | null = null;
  
  // Parametry RSA dla celów edukacyjnych
  private P: bigint = 61n;
  private Q: bigint = 53n;
  private N: bigint = this.P * this.Q; // 3233
  private PHI: bigint = (this.P - 1n) * (this.Q - 1n); // 3120
  private E: bigint = 17n; // Publicna

  constructor() {
    super(
      'Podpis Elektroniczny',
      'Podpisywanie i weryfikacja dokumentów za pomocą RSA-SHA256',
      'Kryptografia asymetryczna'
    );
    this.sha256 = new SHA256Hash();
    // Wyłącz logowanie SHA256 aby nie zaśmiecać logów
    this.sha256.setLogging(false);
    this.generateKeyPair();
  }

  /**
   * Generowanie pary kluczy RSA
   */
  private generateKeyPair(): void {
    const d = this.modularInverse(this.E, this.PHI);
    this.keyPair = {
      publicKey: { n: this.N, e: this.E },
      privateKey: { n: this.N, d: d }
    };
    
    this.logStep('Wygenerowano parę kluczy RSA', '', `n=${this.N}, e=${this.E}, d=${d}`, `Klucz publiczny: (${this.N}, ${this.E}), Klucz prywatny: (${this.N}, ${d})`);
  }

  /**
   * Podpisywanie dokumentu
   * Format: hash dokument||podpis||klucz publiczny
   */
  encrypt(plaintext: string, key: string = ''): string {
    if (!this.keyPair) {
      throw new Error('Para kluczy nie została wygenerowana');
    }

    this.logStep('Rozpoczęcie procesu podpisywania', plaintext);

    // Krok 1: Oblicz hash dokumentu (SHA-256)
    const documentHash = this.sha256.encrypt(plaintext);
    this.logStep('Obliczanie skrótu SHA-256', plaintext, documentHash, 'SHA-256 hash dokumentu');

    // Krok 2: Konwertuj hash na liczbę
    const hashNumber = this.hashToNumber(documentHash);
    this.logStep('Konwersja hasha na liczbę', documentHash, hashNumber.toString(), `Hash jako liczba: ${hashNumber} (użyto pierwszych 3 znaków: ${documentHash.substring(0, 3)})`);

    // Krok 3: Podpisz hash przy użyciu klucza prywatnego
    // signature = hash^d mod n
    const { privateKey } = this.keyPair;
    const signature = this.modularExponentiation(hashNumber, privateKey.d, privateKey.n);
    
    const signatureHex = signature.toString(16).padStart(4, '0');
    this.logStep('Podpisywanie hasha kluczem prywatnym', hashNumber.toString(), signatureHex, `Podpis jako hex: ${signatureHex}, jako liczba: ${signature}`);

    // Krok 4: Zwróć format: dokument|hash|podpis|klucz_publiczny
    const publicKeyStr = `${this.keyPair.publicKey.n},${this.keyPair.publicKey.e}`;
    const result = `${plaintext}|${documentHash}|${signatureHex}|${publicKeyStr}`;
    
    this.logStep('Podpis elektroniczny wygenerowany', plaintext, result, 'Format: dokument|hash|podpis|klucz_publiczny');
    
    return result;
  }

  /**
   * Weryfikacja podpisu dokumentu
   * Sprawdza czy podpis jest prawidłowy dla danego dokumentu
   */
  decrypt(ciphertext: string, key: string = ''): string {
    this.logStep('Rozpoczęcie weryfikacji podpisu', ciphertext);

    try {
      // Parsowanie: dokument|hash|podpis|klucz_publiczny
      const parts = ciphertext.split('|');
      if (parts.length !== 4) {
        throw new Error('Nieprawidłowy format podpisu (oczekiwano: dokument|hash|podpis|klucz_publiczny)');
      }

      const [originalDocument, originalHash, signatureHex, publicKeyStr] = parts;
      this.logStep('Parsing podpisu', ciphertext, `Dokument: ${originalDocument.substring(0, 20)}..., Hash: ${originalHash.substring(0, 16)}...`);

      // Krok 1: Oblicz hash otrzymanego dokumentu
      const currentHash = this.sha256.encrypt(originalDocument);
      this.logStep('Obliczanie skrótu dokumentu', originalDocument, currentHash, 'Hash obliczony z dokumentu');

      // Krok 2: Porównaj z hashem z podpisu
      if (currentHash !== originalHash) {
        const result = '❌ PODPIS NIEWAŻNY\n\nDokument został zmieniony! Hash nie zgadza się.';
        this.logStep('Weryfikacja integralności', currentHash, 'INVALID', 'Hash dokumentu nie zgadza się z hashem z podpisu');
        return result;
      }

      // Krok 3: Parsowanie klucza publicznego
      const [nStr, eStr] = publicKeyStr.split(',');
      const publicKey = {
        n: BigInt(nStr),
        e: BigInt(eStr)
      };
      this.logStep('Wczytanie klucza publicznego', publicKeyStr, `n=${publicKey.n}, e=${publicKey.e}`);

      // Krok 4: Konwersja hasha na liczbę
      const hashNumber = this.hashToNumber(currentHash);
      this.logStep('Konwersja hasha na liczbę', currentHash, hashNumber.toString(), `Hash jako liczba: ${hashNumber}`);
      
      // Krok 5: Konwersja podpisu z hex na liczbę
      const signatureNumber = BigInt('0x' + signatureHex);
      this.logStep('Konwersja podpisu na liczbę', signatureHex, signatureNumber.toString(), `Podpis jako liczba: ${signatureNumber}`);

      // Krok 6: Weryfikacja: hash_odszyfrowany = podpis^e mod n
      const verifiedHash = this.modularExponentiation(signatureNumber, publicKey.e, publicKey.n);
      
      this.logStep('Odszyfrowanie podpisu kluczem publicznym', signatureNumber.toString(), verifiedHash.toString(), `Odszyfrowany hash: ${verifiedHash}`);

      // Krok 7: Porównanie hashów (jako liczby)
      const isValid = hashNumber === verifiedHash;
      
      this.logStep('Porównanie hashów', `Oczekiwany: ${hashNumber}`, `Otrzymany: ${verifiedHash}`, `Zgodność: ${isValid}`);
      
      if (isValid) {
        const result = '✅ PODPIS WAŻNY\n\nDokument nie został zmieniony i pochodzi od podpisującego.';
        this.logStep('Weryfikacja podpisu', currentHash, 'VALID', 'Podpis jest prawidłowy');
        return result;
      } else {
        const result = '❌ PODPIS NIEWAŻNY\n\nPodpis został sfałszowany lub nie pasuje do dokumentu!';
        this.logStep('Weryfikacja podpisu', currentHash, 'INVALID', `Oczekiwano: ${hashNumber}, Otrzymano: ${verifiedHash}`);
        return result;
      }

    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Nieznany błąd weryfikacji';
      this.logStep('Błąd weryfikacji', ciphertext, 'ERROR', errorMsg);
      return `❌ BŁĄD WERYFIKACJI\n\n${errorMsg}`;
    }
  }

  /**
   * Walidacja klucza - dla podpisu nie potrzebujemy klucza
   */
  validateKey(key: string): { valid: boolean; error?: string } {
    return { valid: true, error: 'Podpis elektroniczny generuje własną parę kluczy' };
  }

  getKeyRequirements(): string {
    return 'Podpis elektroniczny: automatycznie generowana para kluczy RSA-2048 (edukacyjnie: RSA-12bit)';
  }

  /**
   * Pobierz klucz publiczny w formacie szesnastkowym
   */
  getPublicKeyHex(): string {
    if (!this.keyPair) {
      throw new Error('Para kluczy nie została wygenerowana');
    }
    const { n, e } = this.keyPair.publicKey;
    return `n: ${n.toString(16)}\ne: ${e.toString(16)}`;
  }

  /**
   * Pobierz klucz prywatny w formacie szesnastkowym (tylko do demonstracji!)
   */
  getPrivateKeyHex(): string {
    if (!this.keyPair) {
      throw new Error('Para kluczy nie została wygenerowana');
    }
    const { n, d } = this.keyPair.privateKey;
    return `n: ${n.toString(16)}\nd: ${d.toString(16)}`;
  }

  /**
   * Modułowe potęgowanie: (base^exp) mod modulus
   * Używa szybkiego algorytmu binary exponentiation
   */
  private modularExponentiation(base: bigint, exp: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    
    let result = 1n;
    base = base % modulus;
    
    while (exp > 0n) {
      if (exp % 2n === 1n) {
        result = (result * base) % modulus;
      }
      exp = exp >> 1n;
      base = (base * base) % modulus;
    }
    
    return result;
  }

  /**
   * Odwrotność modułowa: znajdź x takie że (a*x) mod m = 1
   * Używa rozszerzonego algorytmu Euklidesa
   */
  private modularInverse(a: bigint, m: bigint): bigint {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];

    while (r !== 0n) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
    }

    return old_s < 0n ? old_s + m : old_s;
  }

  /**
   * Konwertuj hash szesnastkowy na liczbę całkowitą
   * Dla małego RSA (n=3233) używamy tylko 3 znaków hasha (12 bitów, max 4095)
   */
  private hashToNumber(hexHash: string): bigint {
    // Weź pierwsze 3 znaki (12 bitów, max 4095) aby zmieścić się w n=3233
    const truncated = hexHash.substring(0, 3);
    return BigInt('0x' + truncated);
  }
}
