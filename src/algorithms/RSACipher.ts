import CryptographicAlgorithm from './CryptographicAlgorithm';

// Pomocnicze funkcje matematyczne dla RSA

// Sprawdza czy liczba jest pierwsza
function isPrime(n: number): boolean {
  if (n < 2) return false;
  if (n === 2) return true;
  if (n % 2 === 0) return false;
  
  const sqrt = Math.floor(Math.sqrt(n));
  for (let i = 3; i <= sqrt; i += 2) {
    if (n % i === 0) return false;
  }
  return true;
}

// Generuje losową liczbę pierwszą w zakresie
function generatePrime(min: number, max: number): number {
  let candidate: number;
  do {
    candidate = Math.floor(Math.random() * (max - min + 1)) + min;
  } while (!isPrime(candidate));
  return candidate;
}

// Największy wspólny dzielnik (algorytm Euklidesa)
function gcd(a: number, b: number): number {
  while (b !== 0) {
    const temp = b;
    b = a % b;
    a = temp;
  }
  return a;
}

// Rozszerzony algorytm Euklidesa - znajduje odwrotność modularną
function modInverse(e: number, phi: number): number {
  let m0 = phi;
  let x0 = 0;
  let x1 = 1;

  if (phi === 1) return 0;

  while (e > 1) {
    const q = Math.floor(e / phi);
    let t = phi;

    phi = e % phi;
    e = t;
    t = x0;

    x0 = x1 - q * x0;
    x1 = t;
  }

  if (x1 < 0) x1 += m0;

  return x1;
}

// Potęgowanie modularne (a^b mod m)
function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent / 2n;
    base = (base * base) % modulus;
  }
  
  return result;
}

export interface RSAKeyPair {
  publicKey: { e: number; n: number };
  privateKey: { d: number; n: number };
}

export default class RSACipher extends CryptographicAlgorithm {
  private keyPair: RSAKeyPair | null = null;

  constructor() {
    super(
      'RSA (Rivest-Shamir-Adleman)',
      'Asymetryczny algorytm kryptograficzny z kluczem publicznym i prywatnym',
      'Kryptografia asymetryczna'
    );
  }

  // Generuje parę kluczy RSA
  generateKeyPair(bitSize: number = 512): RSAKeyPair {
    // Dla celów edukacyjnych używamy małych liczb pierwszych
    // W praktyce RSA wymaga znacznie większych liczb (2048+ bitów)
    const min = bitSize === 512 ? 100 : 50;
    const max = bitSize === 512 ? 300 : 100;
    
    // Generuj dwie różne liczby pierwsze
    const p = generatePrime(min, max);
    let q = generatePrime(min, max);
    while (q === p) {
      q = generatePrime(min, max);
    }

    // Oblicz n = p * q (moduł)
    const n = p * q;

    // Oblicz funkcję Eulera φ(n) = (p-1)(q-1)
    const phi = (p - 1) * (q - 1);

    // Wybierz e (wykładnik publiczny) - zazwyczaj 65537, ale użyjemy mniejszej wartości
    let e = 65537;
    if (e >= phi) {
      e = 17;
    }
    while (gcd(e, phi) !== 1) {
      e++;
    }

    // Oblicz d (wykładnik prywatny) - odwrotność modularna e mod φ(n)
    const d = modInverse(e, phi);

    this.keyPair = {
      publicKey: { e, n },
      privateKey: { d, n }
    };

    return this.keyPair;
  }

  // Pobiera aktualną parę kluczy
  getKeyPair(): RSAKeyPair | null {
    return this.keyPair;
  }

  // Ustawia parę kluczy z zewnątrz
  setKeyPair(keyPair: RSAKeyPair): void {
    this.keyPair = keyPair;
  }

  // Formatuje klucz publiczny do stringa
  formatPublicKey(): string {
    if (!this.keyPair) return '';
    const { e, n } = this.keyPair.publicKey;
    return `${e},${n}`;
  }

  // Formatuje klucz prywatny do stringa
  formatPrivateKey(): string {
    if (!this.keyPair) return '';
    const { d, n } = this.keyPair.privateKey;
    return `${d},${n}`;
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    if (!key || key.trim().length === 0) {
      return { valid: false, error: 'Klucz nie może być pusty' };
    }

    // Format klucza: "e,n" dla publicznego lub "d,n" dla prywatnego
    const parts = key.split(',');
    if (parts.length !== 2) {
      return { 
        valid: false, 
        error: 'Klucz musi być w formacie: "wykładnik,moduł" (np. "17,323")' 
      };
    }

    const [exp, mod] = parts.map(p => parseInt(p.trim(), 10));
    if (isNaN(exp) || isNaN(mod)) {
      return { 
        valid: false, 
        error: 'Wykładnik i moduł muszą być liczbami całkowitymi' 
      };
    }

    if (exp <= 0 || mod <= 0) {
      return { 
        valid: false, 
        error: 'Wykładnik i moduł muszą być liczbami dodatnimi' 
      };
    }

    return { valid: true };
  }

  getKeyRequirements(): string {
    return 'Klucz publiczny (szyfrowanie): "e,n" | Klucz prywatny (deszyfrowanie): "d,n" | Użyj przycisku "Generuj klucze" aby utworzyć nową parę kluczy';
  }

  encrypt(plaintext: string, key: string): string {
    // Parsuj klucz publiczny
    const validation = this.validateKey(key);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const [e, n] = key.split(',').map(p => parseInt(p.trim(), 10));

    // Konwertuj tekst na liczby i szyfruj każdy znak
    const encrypted: number[] = [];
    for (let i = 0; i < plaintext.length; i++) {
      const charCode = plaintext.charCodeAt(i);
      
      // Sprawdź czy znak mieści się w zakresie modułu
      if (charCode >= n) {
        throw new Error(`Znak "${plaintext[i]}" (kod: ${charCode}) przekracza moduł ${n}. Użyj większych liczb pierwszych.`);
      }

      // Szyfrowanie: c = m^e mod n
      const encryptedChar = Number(modPow(BigInt(charCode), BigInt(e), BigInt(n)));
      encrypted.push(encryptedChar);
    }

    // Zwróć jako ciąg liczb rozdzielonych spacjami
    return encrypted.join(' ');
  }

  decrypt(ciphertext: string, key: string): string {
    // Parsuj klucz prywatny
    const validation = this.validateKey(key);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const [d, n] = key.split(',').map(p => parseInt(p.trim(), 10));

    try {
      // Parsuj zaszyfrowane liczby
      const encryptedNumbers = ciphertext.trim().split(/\s+/).map(s => parseInt(s, 10));
      
      // Deszyfruj każdą liczbę
      const decrypted: string[] = [];
      for (const encryptedChar of encryptedNumbers) {
        if (isNaN(encryptedChar)) {
          throw new Error('Nieprawidłowy format szyfrogramu');
        }

        // Deszyfrowanie: m = c^d mod n
        const decryptedChar = Number(modPow(BigInt(encryptedChar), BigInt(d), BigInt(n)));
        decrypted.push(String.fromCharCode(decryptedChar));
      }

      return decrypted.join('');
    } catch (error) {
      throw new Error(`Błąd deszyfrowania: ${error}`);
    }
  }
}
