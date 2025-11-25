import CryptographicAlgorithm from './CryptographicAlgorithm';

// ============================================================================
// Pomocnicze funkcje matematyczne dla ElGamal
// ============================================================================

// Potęgowanie modularne (base^exp % mod)
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp /= 2n;
  }
  return res;
}

// Odwrotność modularna (rozszerzony algorytm Euklidesa)
function modInverse(n: bigint, mod: bigint): bigint {
  let m0 = mod;
  let y = 0n;
  let x = 1n;

  if (mod === 1n) return 0n;

  while (n > 1n) {
    if (mod === 0n) throw new Error("Dzielenie przez zero w modInverse");
    const q = n / mod;
    let t = mod;
    mod = n % mod;
    n = t;
    t = y;
    y = x - q * y;
    x = t;
  }

  if (x < 0n) x += m0;
  return x;
}

// Test pierwszości (prosty, dla małych liczb edukacyjnych)
function isPrime(n: number): boolean {
  if (n <= 1) return false;
  if (n <= 3) return true;
  if (n % 2 === 0 || n % 3 === 0) return false;
  for (let i = 5; i * i <= n; i += 6) {
    if (n % i === 0 || n % (i + 2) === 0) return false;
  }
  return true;
}

// Generowanie losowej liczby pierwszej w zakresie
function generatePrime(min: number, max: number): number {
  let p: number;
  do {
    p = Math.floor(Math.random() * (max - min + 1)) + min;
  } while (!isPrime(p));
  return p;
}

// Znajdowanie pierwiastka pierwotnego modulo p
// g jest pierwiastkiem pierwotnym modulo p, jeśli rząd g wynosi p-1
function findPrimitiveRoot(p: number): number {
  const phi = p - 1;
  const factors: number[] = [];
  
  // Znajdź czynniki pierwsze phi
  let n = phi;
  for (let i = 2; i * i <= n; i++) {
    if (n % i === 0) {
      factors.push(i);
      while (n % i === 0) n /= i;
    }
  }
  if (n > 1) factors.push(n);

  // Sprawdź kandydatów na g
  for (let g = 2; g <= p; g++) {
    let isPrimitive = true;
    for (const factor of factors) {
      // Sprawdź czy g^(phi/factor) mod p != 1
      if (modPow(BigInt(g), BigInt(phi / factor), BigInt(p)) === 1n) {
        isPrimitive = false;
        break;
      }
    }
    if (isPrimitive) return g;
  }
  return -1; // Nie znaleziono (nie powinno się zdarzyć dla liczb pierwszych)
}

// Największy wspólny dzielnik
function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) {
    let t = b;
    b = a % b;
    a = t;
  }
  return a;
}

export interface ElGamalKeyPair {
  publicKey: {
    p: string; // Liczba pierwsza (moduł)
    g: string; // Generator (pierwiastek pierwotny)
    y: string; // Klucz publiczny y = g^x mod p
  };
  privateKey: {
    x: string; // Tajny wykładnik
    p: string; // Potrzebne też przy deszyfrowaniu
  };
}

export default class ElGamalCipher extends CryptographicAlgorithm {
  private keyPair: ElGamalKeyPair | null = null;

  constructor() {
    super(
      'ElGamal',
      'Asymetryczny system szyfrowania oparty na problemie logarytmu dyskretnego',
      'Kryptografia asymetryczna'
    );
  }

  // ========================================================================
  // Zarządzanie kluczami
  // ========================================================================

  generateKeyPair(): ElGamalKeyPair {
    this.logStep('ElGamal: Rozpoczęcie generowania kluczy', undefined, undefined, 'Szukamy p, g, x');

    // 1. Wybierz dużą liczbę pierwszą p
    // Dla celów edukacyjnych używamy zakresu pozwalającego na kodowanie znaków ASCII (>255)
    const minP = 300;
    const maxP = 1000;
    const p = generatePrime(minP, maxP);
    this.logStep('ElGamal: Wygenerowano liczbę pierwszą p', undefined, `p = ${p}`, 'Moduł układu');

    // 2. Znajdź generator g (pierwiastek pierwotny modulo p)
    const g = findPrimitiveRoot(p);
    this.logStep('ElGamal: Znaleziono generator g', undefined, `g = ${g}`, `Pierwiastek pierwotny modulo ${p}`);

    // 3. Wybierz losowy klucz prywatny x taki, że 1 < x < p-1
    const x = Math.floor(Math.random() * (p - 2)) + 2;
    this.logStep('ElGamal: Wylosowano klucz prywatny x', undefined, `x = ${x}`, `1 < x < ${p-1}`);

    // 4. Oblicz klucz publiczny y = g^x mod p
    const y = modPow(BigInt(g), BigInt(x), BigInt(p));
    this.logStep('ElGamal: Obliczono część klucza publicznego y', 
      `g=${g}, x=${x}, p=${p}`, 
      `y = ${y}`, 
      'y = g^x mod p'
    );

    this.keyPair = {
      publicKey: {
        p: p.toString(),
        g: g.toString(),
        y: y.toString()
      },
      privateKey: {
        x: x.toString(),
        p: p.toString()
      }
    };

    this.logStep('ElGamal: Zakończono generowanie kluczy', 
      undefined, 
      `Publiczny: (p=${p}, g=${g}, y=${y})\nPrywatny: x=${x}`,
      'Gotowe do szyfrowania'
    );

    return this.keyPair;
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    if (!key) return { valid: false, error: 'Klucz jest pusty' };

    // Format publiczny: p,g,y
    // Format prywatny: x,p
    const parts = key.split(',');
    
    if (parts.length === 3) {
      // Publiczny
      const [p, g, y] = parts.map(n => parseInt(n.trim()));
      if (isNaN(p) || isNaN(g) || isNaN(y)) return { valid: false, error: 'Elementy klucza muszą być liczbami' };
      if (!isPrime(p)) return { valid: false, error: 'p musi być liczbą pierwszą' };
      return { valid: true };
    } else if (parts.length === 2) {
      // Prywatny
      const [x, p] = parts.map(n => parseInt(n.trim()));
      if (isNaN(x) || isNaN(p)) return { valid: false, error: 'Elementy klucza muszą być liczbami' };
      return { valid: true };
    } else {
      return { valid: false, error: 'Nieprawidłowy format klucza. Publiczny: "p,g,y", Prywatny: "x,p"' };
    }
  }

  getKeyRequirements(): string {
    return 'Publiczny: "p,g,y" (np. "467,2,132") | Prywatny: "x,p" (np. "123,467")';
  }

  // ========================================================================
  // Szyfrowanie i Deszyfrowanie
  // ========================================================================

  encrypt(plaintext: string, key: string): string {
    // Oczekujemy klucza publicznego: p,g,y
    this.logStep('Rozpoczęcie szyfrowania ElGamal', plaintext, undefined, `Klucz: ${key}`);
    
    const validation = this.validateKey(key);
    if (!validation.valid) throw new Error(validation.error);
    
    const parts = key.split(',');
    if (parts.length !== 3) throw new Error('Do szyfrowania wymagany jest klucz publiczny (p,g,y)');
    
    const [pStr, gStr, yStr] = parts;
    const p = BigInt(pStr);
    const g = BigInt(gStr);
    const y = BigInt(yStr);

    const encryptedPairs: string[] = [];

    for (let i = 0; i < plaintext.length; i++) {
      const m = BigInt(plaintext.charCodeAt(i));
      
      if (m >= p) {
        throw new Error(`Znak "${plaintext[i]}" ma kod ${m}, który jest większy niż moduł p=${p}. Wygeneruj większe klucze.`);
      }

      // 1. Wybierz losowe k (klucz efemeryczny) takie, że 1 < k < p-1 i gcd(k, p-1) = 1
      // (warunek gcd nie jest ściśle wymagany do szyfrowania, ale dobra praktyka w niektórych wariantach, tutaj wystarczy losowe)
      let k: bigint;
      do {
        k = BigInt(Math.floor(Math.random() * (Number(p) - 2)) + 1);
      } while (gcd(k, p - 1n) !== 1n); // Dla bezpieczeństwa

      // 2. Oblicz a = g^k mod p
      const a = modPow(g, k, p);

      // 3. Oblicz b = (y^k * m) mod p
      const y_k = modPow(y, k, p);
      const b = (y_k * m) % p;

      if (i < 3) {
        this.logStep(`Szyfrowanie znaku '${plaintext[i]}'`, 
          `m=${m}, k=${k}`, 
          `a=${a}, b=${b}`, 
          `a = ${g}^${k} mod ${p}\nb = (${y}^${k} * ${m}) mod ${p}`
        );
      }

      encryptedPairs.push(`${a}:${b}`);
    }

    if (plaintext.length > 3) {
      this.logStep('...', undefined, undefined, `Zaszyfrowano pozostałe ${plaintext.length - 3} znaków`);
    }

    const result = encryptedPairs.join(' ');
    this.logStep('Zakończono szyfrowanie', plaintext, result, 'Format wyjściowy: a1:b1 a2:b2 ...');
    
    return result;
  }

  decrypt(ciphertext: string, key: string): string {
    // Oczekujemy klucza prywatnego: x,p
    this.logStep('Rozpoczęcie deszyfrowania ElGamal', ciphertext, undefined, `Klucz: ${key}`);

    const validation = this.validateKey(key);
    if (!validation.valid) throw new Error(validation.error);

    const parts = key.split(',');
    if (parts.length !== 2) throw new Error('Do deszyfrowania wymagany jest klucz prywatny (x,p)');

    const [xStr, pStr] = parts;
    const x = BigInt(xStr);
    const p = BigInt(pStr);

    const pairs = ciphertext.trim().split(/\s+/);
    let decrypted = '';

    for (let i = 0; i < pairs.length; i++) {
      const pair = pairs[i];
      if (!pair.includes(':')) throw new Error(`Nieprawidłowy format pary: ${pair}`);
      
      const [aStr, bStr] = pair.split(':');
      const a = BigInt(aStr);
      const b = BigInt(bStr);

      // Deszyfrowanie: m = b * (a^x)^-1 mod p
      // Co jest równoważne: m = b * a^(p-1-x) mod p (z Małego Twierdzenia Fermata)
      
      // 1. Oblicz s = a^x mod p
      const s = modPow(a, x, p);
      
      // 2. Oblicz odwrotność s modulo p
      const sInv = modInverse(s, p);

      // 3. Oblicz m = (b * sInv) mod p
      const m = (b * sInv) % p;

      const char = String.fromCharCode(Number(m));
      decrypted += char;

      if (i < 3) {
        this.logStep(`Deszyfrowanie pary ${pair}`, 
          `a=${a}, b=${b}`, 
          `m=${m} ('${char}')`, 
          `s = ${a}^${x} mod ${p} = ${s}\nm = ${b} * ${s}^-1 mod ${p}`
        );
      }
    }

    this.logStep('Zakończono deszyfrowanie', ciphertext, decrypted);
    return decrypted;
  }
}
