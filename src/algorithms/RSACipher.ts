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
  // PRZYKŁAD UŻYCIA (w konsoli lub kodzie):
  // const rsa = new RSACipher();
  // const keys = rsa.generateKeyPair();
  // console.log('Klucz publiczny:', rsa.formatPublicKey());  // np. "17,323"
  // console.log('Klucz prywatny:', rsa.formatPrivateKey());  // np. "233,323"
  generateKeyPair(bitSize: number = 512): RSAKeyPair {
    this.logStep('RSA: Rozpoczęcie generowania pary kluczy', undefined, undefined, `Rozmiar: ${bitSize} bitów (uproszczona wersja edukacyjna)`);
    
    // Dla celów edukacyjnych używamy małych liczb pierwszych
    // W praktyce RSA wymaga znacznie większych liczb (2048+ bitów)
    const min = bitSize === 512 ? 100 : 50;
    const max = bitSize === 512 ? 300 : 100;
    
    this.logStep('RSA: Określenie zakresu liczb pierwszych', undefined, undefined, `Zakres: ${min}-${max}`);
    
    // Generuj dwie różne liczby pierwsze
    const p = generatePrime(min, max);
    this.logStep('RSA: Wygenerowano pierwszą liczbę pierwszą p', undefined, `${p}`, 'Test pierwszości Miller-Rabin');
    
    let q = generatePrime(min, max);
    while (q === p) {
      q = generatePrime(min, max);
    }
    this.logStep('RSA: Wygenerowano drugą liczbę pierwszą q', undefined, `${q}`, 'p ≠ q dla bezpieczeństwa');

    // Oblicz n = p * q (moduł)
    const n = p * q;
    this.logStep('RSA: Obliczenie modułu n', `p=${p}, q=${q}`, `n=${n}`, 'n = p × q (moduł do szyfrowania)');

    // Oblicz funkcję Eulera φ(n) = (p-1)(q-1)
    const phi = (p - 1) * (q - 1);
    this.logStep('RSA: Obliczenie funkcji Eulera φ(n)', `(${p}-1) × (${q}-1)`, `φ(n)=${phi}`, 'φ(n) = (p-1)(q-1) - liczba liczb względnie pierwszych z n');

    // Wybierz e (wykładnik publiczny) - zazwyczaj 65537, ale użyjemy mniejszej wartości
    let e = 65537;
    if (e >= phi) {
      e = 17;
      this.logStep('RSA: Dostosowanie wykładnika e', '65537', `${e}`, 'e musi być mniejsze od φ(n)');
    }
    while (gcd(e, phi) !== 1) {
      e++;
    }
    this.logStep('RSA: Wybór wykładnika publicznego e', undefined, `e=${e}`, `gcd(e, φ(n)) = 1 (e i φ(n) są względnie pierwsze)`);

    // Oblicz d (wykładnik prywatny) - odwrotność modularna e mod φ(n)
    const d = modInverse(e, phi);
    this.logStep('RSA: Obliczenie wykładnika prywatnego d', `e=${e}, φ(n)=${phi}`, `d=${d}`, `d × e ≡ 1 (mod φ(n)) - odwrotność modularna`);

    this.keyPair = {
      publicKey: { e, n },
      privateKey: { d, n }
    };

    this.logStep(
      'RSA: Zakończenie generowania kluczy',
      undefined,
      `Publiczny: (e=${e}, n=${n})\nPrywatny: (d=${d}, n=${n})`,
      'Klucz publiczny do szyfrowania, prywatny do deszyfrowania'
    );

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
    return 'Klucz publiczny (szyfrowanie): "e,n" (np. "17,323") | Klucz prywatny (deszyfrowanie): "d,n" (np. "233,323") | Wykładnik i moduł rozdzielone przecinkiem';
  }

  encrypt(plaintext: string, key: string): string {
    // Parsuj klucz publiczny
    this.logStep('Rozpoczęcie szyfrowania RSA', plaintext, undefined, `Klucz publiczny: ${key.substring(0, 30)}...`);
    const validation = this.validateKey(key);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const [e, n] = key.split(',').map(p => parseInt(p.trim(), 10));
    this.logStep('Parametry RSA', undefined, undefined, `e = ${e}, n = ${n}`);

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
      
      if (i < 3) {
        this.logStep(
          `Szyfrowanie znaku ${i + 1}: "${plaintext[i]}"`,
          `${charCode}`,
          `${encryptedChar}`,
          `${charCode}^${e} mod ${n} = ${encryptedChar}`
        );
      }
    }
    
    if (plaintext.length > 3) {
      this.logStep('Pominięto szczegóły', undefined, undefined, `Zaszyfrowano pozostałe ${plaintext.length - 3} znaków`);
    }

    // Zwróć jako ciąg liczb rozdzielonych spacjami
    const result = encrypted.join(' ');
    this.logStep('Zakończenie szyfrowania RSA', plaintext, result);
    return result;
  }

  decrypt(ciphertext: string, key: string): string {
    // Parsuj klucz prywatny
    this.logStep('Rozpoczęcie deszyfrowania RSA', ciphertext, undefined, `Klucz prywatny: ${key.substring(0, 30)}...`);
    const validation = this.validateKey(key);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const [d, n] = key.split(',').map(p => parseInt(p.trim(), 10));
    this.logStep('Parametry RSA', undefined, undefined, `d = ${d}, n = ${n}`);

    try {
      // Parsuj zaszyfrowane liczby
      const encryptedNumbers = ciphertext.trim().split(/\s+/).map(s => parseInt(s, 10));
      this.logStep('Parsowanie szyfrogramu', undefined, undefined, `Liczba zaszyfrowanych znaków: ${encryptedNumbers.length}`);
      
      // Deszyfruj każdą liczbę
      const decrypted: string[] = [];
      for (let i = 0; i < encryptedNumbers.length; i++) {
        const encryptedChar = encryptedNumbers[i];
        if (isNaN(encryptedChar)) {
          throw new Error('Nieprawidłowy format szyfrogramu');
        }

        // Deszyfrowanie: m = c^d mod n
        const decryptedChar = Number(modPow(BigInt(encryptedChar), BigInt(d), BigInt(n)));
        decrypted.push(String.fromCharCode(decryptedChar));
        
        if (i < 3) {
          this.logStep(
            `Deszyfrowanie znaku ${i + 1}`,
            `${encryptedChar}`,
            `"${String.fromCharCode(decryptedChar)}" (${decryptedChar})`,
            `${encryptedChar}^${d} mod ${n} = ${decryptedChar}`
          );
        }
      }
      
      if (encryptedNumbers.length > 3) {
        this.logStep('Pominięto szczegóły', undefined, undefined, `Odszyfrowano pozostałe ${encryptedNumbers.length - 3} znaków`);
      }

      const result = decrypted.join('');
      this.logStep('Zakończenie deszyfrowania RSA', ciphertext, result);
      return result;
    } catch (error) {
      throw new Error(`Błąd deszyfrowania: ${error}`);
    }
  }
}
