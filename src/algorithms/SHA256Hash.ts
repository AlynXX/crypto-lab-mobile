// ============================================================================
// SHA-256 Hash Function
// Secure Hash Algorithm 256-bit
// ============================================================================
// Implementacja ręczna SHA-256 bez zewnętrznych bibliotek
// Algorytm oparty na standardzie FIPS 180-4

import CryptographicAlgorithm from './CryptographicAlgorithm';

export default class SHA256Hash extends CryptographicAlgorithm {
  private K: number[] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  private H: number[] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  constructor() {
    super(
      'SHA-256',
      'Secure Hash Algorithm - 256-bit',
      'Hash Function'
    );
  }

  /**
   * SHA-256 może przyjmować dowolny tekst, nie potrzebuje klucza
   */
  encrypt(plaintext: string, key: string = ''): string {
    this.logStep('SHA-256 Hash Process Started', plaintext);
    
    // Konwersja tekstu na bajty
    const bytes = this.stringToBytes(plaintext);
    this.logStep('Text converted to bytes', plaintext, bytes.map(b => b.toString(16).padStart(2, '0')).join(''));

    // Główny proces haszowania
    const hash = this.sha256(bytes);
    const hexHash = this.bytesToHex(hash);
    
    this.logStep('SHA-256 Hash Generated', plaintext, hexHash);
    return hexHash;
  }

  /**
   * SHA-256 to funkcja jednokierunkowa - nie można odwrócić
   */
  decrypt(ciphertext: string, key: string = ''): string {
    this.logStep('SHA-256 Decryption Attempt', ciphertext, 'N/A - SHA-256 is one-way function');
    return 'SHA-256 jest funkcją jednokierunkową i nie może być odwrócona';
  }

  /**
   * SHA-256 nie wymaga klucza
   */
  validateKey(key: string): { valid: boolean; error?: string } {
    return { valid: true, error: 'SHA-256 nie wymaga klucza' };
  }

  getKeyRequirements(): string {
    return 'SHA-256 nie wymaga klucza - funkcja haszująca (jednokierunkowa)';
  }

  /**
   * Główny algorytm SHA-256
   */
  private sha256(message: number[]): number[] {
    // Preprocessing
    const preprocessed = this.preprocess(message);

    // Inicjalizacja zmiennych roboczych
    const H = [...this.H];

    // Przetwarzanie każdego bloku 512-bitowego
    for (let i = 0; i < preprocessed.length; i += 16) {
      const block = preprocessed.slice(i, i + 16);
      const W = this.prepareSchedule(block);
      const [a, b, c, d, e, f, g, h] = [...H];

      let A = a, B = b, C = c, D = d, E = e, F = f, G = g, H_temp = h;

      // 64 rundy
      for (let t = 0; t < 64; t++) {
        const T1 = (H_temp + this.Sigma1(E) + this.Ch(E, F, G) + this.K[t] + W[t]) >>> 0;
        const T2 = (this.Sigma0(A) + this.Maj(A, B, C)) >>> 0;
        H_temp = G;
        G = F;
        F = E;
        E = (D + T1) >>> 0;
        D = C;
        C = B;
        B = A;
        A = (T1 + T2) >>> 0;
      }

      H[0] = (H[0] + A) >>> 0;
      H[1] = (H[1] + B) >>> 0;
      H[2] = (H[2] + C) >>> 0;
      H[3] = (H[3] + D) >>> 0;
      H[4] = (H[4] + E) >>> 0;
      H[5] = (H[5] + F) >>> 0;
      H[6] = (H[6] + G) >>> 0;
      H[7] = (H[7] + H_temp) >>> 0;
    }

    // Konwersja wyników na bajty
    const result: number[] = [];
    for (let i = 0; i < 8; i++) {
      result.push((H[i] >>> 24) & 0xff);
      result.push((H[i] >>> 16) & 0xff);
      result.push((H[i] >>> 8) & 0xff);
      result.push(H[i] & 0xff);
    }

    return result;
  }

  /**
   * Preprocessing: padding i długość wiadomości
   */
  private preprocess(message: number[]): number[] {
    const msgLen = message.length * 8; // długość w bitach
    
    // Dodaj bit '1' (0x80) po wiadomości
    const padded = [...message, 0x80];

    // Dodaj zera aż do 56 bajtów modulo 64
    while ((padded.length % 64) !== 56) {
      padded.push(0x00);
    }

    // Dodaj długość wiadomości (8 bajtów big-endian)
    for (let i = 7; i >= 0; i--) {
      padded.push((msgLen >>> (i * 8)) & 0xff);
    }

    // Konwertuj na 32-bitowe słowa
    const result: number[] = [];
    for (let i = 0; i < padded.length; i += 4) {
      const word = (padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3];
      result.push(word >>> 0);
    }

    return result;
  }

  /**
   * Przygotowanie harmonogramu wiadomości
   */
  private prepareSchedule(block: number[]): number[] {
    const W: number[] = [];

    // Pierwsze 16 słów to blok
    for (let i = 0; i < 16; i++) {
      W[i] = block[i];
    }

    // Oblicz pozostałe 48 słów
    for (let i = 16; i < 64; i++) {
      const s0 = this.sigma0(W[i - 15]);
      const s1 = this.sigma1(W[i - 2]);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    return W;
  }

  // Funkcje logiczne SHA-256
  private Ch(x: number, y: number, z: number): number {
    return (x & y) ^ (~x & z);
  }

  private Maj(x: number, y: number, z: number): number {
    return (x & y) ^ (x & z) ^ (y & z);
  }

  private Sigma0(x: number): number {
    return this.rightRotate(x, 2) ^ this.rightRotate(x, 13) ^ this.rightRotate(x, 22);
  }

  private Sigma1(x: number): number {
    return this.rightRotate(x, 6) ^ this.rightRotate(x, 11) ^ this.rightRotate(x, 25);
  }

  private sigma0(x: number): number {
    return this.rightRotate(x, 7) ^ this.rightRotate(x, 18) ^ (x >>> 3);
  }

  private sigma1(x: number): number {
    return this.rightRotate(x, 17) ^ this.rightRotate(x, 19) ^ (x >>> 10);
  }

  /**
   * Rotacja bitów w prawo
   */
  private rightRotate(value: number, shift: number): number {
    return ((value >>> shift) | (value << (32 - shift))) >>> 0;
  }

  /**
   * Konwersja stringa na tablicę bajtów
   */
  private stringToBytes(str: string): number[] {
    const bytes: number[] = [];
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code < 128) {
        bytes.push(code);
      } else if (code < 2048) {
        bytes.push(0xc0 | (code >> 6));
        bytes.push(0x80 | (code & 0x3f));
      } else if (code < 65536) {
        bytes.push(0xe0 | (code >> 12));
        bytes.push(0x80 | ((code >> 6) & 0x3f));
        bytes.push(0x80 | (code & 0x3f));
      }
    }
    return bytes;
  }

  /**
   * Konwersja tablicy bajtów na heksadecymalny string
   */
  private bytesToHex(bytes: number[]): string {
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
