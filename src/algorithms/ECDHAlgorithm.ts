import CryptographicAlgorithm from './CryptographicAlgorithm';

// Typ punktu na krzywej eliptycznej
interface Point {
  x: bigint;
  y: bigint;
  isInfinity: boolean;
}

// Parametry krzywej eliptycznej: y^2 = x^3 + ax + b (mod p)
// Używamy małych liczb dla celów edukacyjnych
const CURVE = {
  p: 487n, // Liczba pierwsza (moduł)
  a: 5n,   // Współczynnik a
  b: 19n,  // Współczynnik b
  // Punkt bazowy G (generator)
  G: { x: 17n, y: 141n, isInfinity: false } as Point,
  n: 0n // Rząd punktu G (obliczymy lub zostawimy 0 jeśli niepotrzebne do prostego ECDH)
};

export default class ECDHAlgorithm extends CryptographicAlgorithm {
  private privateKey: bigint | null = null;
  private publicKey: Point | null = null;

  constructor() {
    super(
      'ECDH (Elliptic Curve Diffie-Hellman)',
      'Protokół uzgadniania kluczy oparty na krzywych eliptycznych (zaimplementowany jako ECIES dla demonstracji)',
      'Kryptografia asymetryczna'
    );
  }

  // ========================================================================
  // Operacje matematyczne na krzywych eliptycznych
  // ========================================================================

  // Dodawanie punktów: P + Q
  private addPoints(P: Point, Q: Point): Point {
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;

    const { p, a } = CURVE;

    // Jeśli x są równe
    if (P.x === Q.x) {
      // Jeśli y są przeciwne (P + (-P) = 0)
      if ((P.y + Q.y) % p === 0n || P.y === p - Q.y) {
        return { x: 0n, y: 0n, isInfinity: true };
      }
      // Jeśli to ten sam punkt, ale y=0, to podwojenie daje nieskończoność
      if (P.y === Q.y && P.y === 0n) {
        return { x: 0n, y: 0n, isInfinity: true };
      }
    }

    let m: bigint;
    
    if (P.x === Q.x && P.y === Q.y) {
      // Podwojenie punktu: m = (3x^2 + a) / (2y)
      const numerator = (3n * P.x * P.x + a) % p;
      const denominator = (2n * P.y) % p;
      m = (numerator * this.modInverse(denominator, p)) % p;
    } else {
      // Dodawanie różnych punktów: m = (y2 - y1) / (x2 - x1)
      const numerator = (Q.y - P.y) % p;
      const denominator = (Q.x - P.x) % p;
      m = (numerator * this.modInverse(denominator, p)) % p;
    }

    // Normalizacja ujemnego m
    if (m < 0n) m += p;

    // x3 = m^2 - x1 - x2
    let x3 = (m * m - P.x - Q.x) % p;
    if (x3 < 0n) x3 += p;

    // y3 = m(x1 - x3) - y1
    let y3 = (m * (P.x - x3) - P.y) % p;
    if (y3 < 0n) y3 += p;

    return { x: x3, y: y3, isInfinity: false };
  }

  // Mnożenie skalarne: k * P (algorytm Double-and-Add)
  private multiplyPoint(k: bigint, P: Point): Point {
    let result: Point = { x: 0n, y: 0n, isInfinity: true };
    let addend = P;

    while (k > 0n) {
      if (k & 1n) {
        result = this.addPoints(result, addend);
      }
      addend = this.addPoints(addend, addend);
      k >>= 1n;
    }

    return result;
  }

  // Odwrotność modularna (Rozszerzony Algorytm Euklidesa)
  private modInverse(a: bigint, m: bigint): bigint {
    let m0 = m;
    let y = 0n;
    let x = 1n;

    if (m === 1n) return 0n;

    // Obsługa ujemnych liczb
    if (a < 0n) a += m;

    while (a > 1n) {
      if (m === 0n) throw new Error("Dzielenie przez zero w modInverse");
      const q = a / m;
      let t = m;
      m = a % m;
      a = t;
      t = y;
      y = x - q * y;
      x = t;
    }

    if (x < 0n) x += m0;
    return x;
  }

  // ========================================================================
  // Zarządzanie kluczami
  // ========================================================================

  generateKeyPair(): { privateKey: string; publicKey: string } {
    this.logStep('ECDH: Generowanie pary kluczy', undefined, undefined, `Krzywa: y^2 = x^3 + ${CURVE.a}x + ${CURVE.b} (mod ${CURVE.p})`);
    
    // Losowy klucz prywatny d z zakresu [1, p-1]
    // W praktyce powinien być z zakresu [1, n-1], gdzie n to rząd punktu G
    const d = BigInt(Math.floor(Math.random() * (Number(CURVE.p) - 2)) + 1);
    this.privateKey = d;
    this.logStep('ECDH: Wylosowano klucz prywatny d', undefined, `d = ${d}`);

    // Klucz publiczny Q = d * G
    this.publicKey = this.multiplyPoint(d, CURVE.G);
    this.logStep('ECDH: Obliczono klucz publiczny Q = d * G', 
      `G=(${CURVE.G.x}, ${CURVE.G.y})`, 
      `Q=(${this.publicKey.x}, ${this.publicKey.y})`
    );

    return {
      privateKey: d.toString(),
      publicKey: `${this.publicKey.x},${this.publicKey.y}`
    };
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    if (!key) return { valid: false, error: 'Klucz jest pusty' };
    
    // Sprawdź czy to klucz publiczny (x,y) czy prywatny (d)
    if (key.includes(',')) {
      const parts = key.split(',');
      if (parts.length !== 2) return { valid: false, error: 'Klucz publiczny musi być w formacie "x,y"' };
      try {
        BigInt(parts[0]);
        BigInt(parts[1]);
      } catch {
        return { valid: false, error: 'Współrzędne muszą być liczbami' };
      }
    } else {
      try {
        BigInt(key);
      } catch {
        return { valid: false, error: 'Klucz prywatny musi być liczbą' };
      }
    }
    return { valid: true };
  }

  getKeyRequirements(): string {
    return 'Klucz publiczny: "x,y" | Klucz prywatny: liczba całkowita';
  }

  // ========================================================================
  // Szyfrowanie i Deszyfrowanie (ECIES - Simplified)
  // ========================================================================

  encrypt(plaintext: string, key: string): string {
    // key to klucz publiczny odbiorcy (Q)
    this.logStep('Rozpoczęcie szyfrowania ECIES (z użyciem ECDH)', plaintext, undefined, `Klucz odbiorcy: ${key}`);
    
    const validation = this.validateKey(key);
    if (!validation.valid) throw new Error(validation.error);
    if (!key.includes(',')) throw new Error('Do szyfrowania wymagany jest klucz publiczny (x,y)');

    const [qx, qy] = key.split(',').map(c => BigInt(c));
    const Q: Point = { x: qx, y: qy, isInfinity: false };

    // 1. Wygeneruj tymczasową parę kluczy (k, R)
    const k = BigInt(Math.floor(Math.random() * (Number(CURVE.p) - 2)) + 1);
    const R = this.multiplyPoint(k, CURVE.G); // R = k * G
    
    this.logStep('Generowanie klucza efemerycznego', undefined, 
      `k=${k}, R=(${R.x}, ${R.y})`, 
      'R zostanie dołączone do szyfrogramu'
    );

    // 2. Oblicz wspólny sekret S = k * Q
    const S = this.multiplyPoint(k, Q);
    this.logStep('Obliczanie wspólnego sekretu (ECDH)', 
      `k=${k}, Q=(${Q.x}, ${Q.y})`, 
      `S = k * Q = (${S.x}, ${S.y})`
    );

    if (S.isInfinity) {
      throw new Error('Obliczony punkt jest w nieskończoności. Spróbuj ponownie (zły klucz lub pech).');
    }

    // 3. Użyj współrzędnej x punktu S jako klucza symetrycznego do szyfrowania XOR
    // W prawdziwym ECIES użylibyśmy KDF (Key Derivation Function)
    const symmetricKey = Number(S.x);
    this.logStep('Wyprowadzenie klucza symetrycznego', `S.x=${S.x}`, `Klucz=${symmetricKey}`, 'Używamy S.x jako klucza XOR');

    // 4. Szyfruj wiadomość
    const encryptedBytes: number[] = [];
    for (let i = 0; i < plaintext.length; i++) {
      const charCode = plaintext.charCodeAt(i);
      const encryptedChar = charCode ^ symmetricKey; // Prosty XOR
      encryptedBytes.push(encryptedChar);
    }

    const ciphertextBody = encryptedBytes.map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Format wyjściowy: Rx,Ry|CiphertextHex
    const result = `${R.x},${R.y}|${ciphertextBody}`;
    
    this.logStep('Zakończenie szyfrowania', 
      plaintext, 
      result, 
      `Dołączono klucz publiczny R: (${R.x},${R.y})`
    );

    return result;
  }

  decrypt(ciphertext: string, key: string): string {
    // key to klucz prywatny odbiorcy (d)
    this.logStep('Rozpoczęcie deszyfrowania ECIES', ciphertext, undefined, `Klucz prywatny: ${key}`);

    const validation = this.validateKey(key);
    if (!validation.valid) throw new Error(validation.error);
    if (key.includes(',')) throw new Error('Do deszyfrowania wymagany jest klucz prywatny (liczba)');

    const d = BigInt(key);

    // 1. Parsuj szyfrogram: Rx,Ry|CiphertextHex
    const parts = ciphertext.split('|');
    if (parts.length !== 2) throw new Error('Nieprawidłowy format szyfrogramu. Oczekiwano "Rx,Ry|Dane"');

    const [rStr, bodyHex] = parts;
    const [rx, ry] = rStr.split(',').map(c => BigInt(c));
    const R: Point = { x: rx, y: ry, isInfinity: false };

    this.logStep('Odczytanie klucza efemerycznego R', ciphertext, `R=(${R.x}, ${R.y})`);

    // 2. Oblicz wspólny sekret S = d * R
    const S = this.multiplyPoint(d, R);
    this.logStep('Obliczanie wspólnego sekretu (ECDH)', 
      `d=${d}, R=(${R.x}, ${R.y})`, 
      `S = d * R = (${S.x}, ${S.y})`
    );

    // 3. Wyprowadź klucz symetryczny
    const symmetricKey = Number(S.x);
    this.logStep('Wyprowadzenie klucza symetrycznego', `S.x=${S.x}`, `Klucz=${symmetricKey}`);

    // 4. Deszyfruj wiadomość
    let decrypted = '';
    for (let i = 0; i < bodyHex.length; i += 2) {
      const byteHex = bodyHex.substr(i, 2);
      const byteVal = parseInt(byteHex, 16);
      const charCode = byteVal ^ symmetricKey;
      decrypted += String.fromCharCode(charCode);
    }

    this.logStep('Zakończenie deszyfrowania', ciphertext, decrypted);
    return decrypted;
  }
}
