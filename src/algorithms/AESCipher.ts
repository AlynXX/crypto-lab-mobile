
import CryptographicAlgorithm from './CryptographicAlgorithm';

// Stałe AES
const SBOX = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

const INV_SBOX = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

const RCON = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

type AESMode = 'ECB' | 'CBC' | 'CTR'; // Rozszerzalne o inne tryby w przyszłości

export default class AESCipher extends CryptographicAlgorithm {
  private mode: AESMode;
  public static readonly DEFAULT_KEY = '2b7e151628aed2a6abf7158809cf4f3c'; // Domyślny klucz AES-128

  constructor() {
    super(
      'AES (Advanced Encryption Standard)',
      'Symetryczny szyfr blokowy z możliwością wyboru trybu (ECB, CBC, CTR)',
      'Szyfry symetryczne'
    );
    this.mode = 'ECB'; // Domyślny tryb
  }

  // Ustawia tryb pracy AES
  setMode(mode: AESMode): void {
    this.mode = mode;
  }

  // Pobiera aktualny tryb
  getMode(): AESMode {
    return this.mode;
  }

  // Pobiera dostępne tryby
  getAvailableModes(): AESMode[] {
    return ['ECB', 'CBC', 'CTR'];
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    if (!key || key.trim().length === 0) {
      return { valid: false, error: 'Klucz nie może być pusty' };
    }

    // Sprawdź czy klucz jest w formacie hex
    const hexPattern = /^[0-9a-fA-F]+$/;
    if (!hexPattern.test(key)) {
      return { valid: false, error: 'Klucz musi być ciągiem znaków szesnastkowych (0-9, A-F)' };
    }

    // Klucz musi mieć długość 32, 48 lub 64 znaków hex (128, 192 lub 256 bitów)
    if (key.length !== 32 && key.length !== 48 && key.length !== 64) {
      return {
        valid: false,
        error: 'Klucz musi mieć długość 32 (AES-128), 48 (AES-192) lub 64 (AES-256) znaków hex'
      };
    }

    return { valid: true };
  }

  getKeyRequirements(): string {
    return `Tryb: ${this.mode} | Klucz hex: 32 znaki (AES-128), 48 (AES-192) lub 64 (AES-256). Domyślny: ${AESCipher.DEFAULT_KEY}`;
  }

  encrypt(plaintext: string, key: string): string {
    this.logStep(`Rozpoczęcie szyfrowania AES w trybie ${this.mode}`, plaintext, undefined, `Długość klucza: ${key.length * 4} bitów`);
    let result: string;
    if (this.mode === 'ECB') {
      result = this.encryptECB(plaintext, key);
    } else if (this.mode === 'CBC') {
      result = this.encryptCBC(plaintext, key);
    } else if (this.mode === 'CTR') {
      result = this.encryptCTR(plaintext, key);
    } else {
      throw new Error(`Tryb ${this.mode} nie jest obsługiwany`);
    }
    this.logStep('Zakończenie szyfrowania AES', plaintext, result);
    return result;
  }

  decrypt(ciphertext: string, key: string): string {
    this.logStep(`Rozpoczęcie deszyfrowania AES w trybie ${this.mode}`, ciphertext, undefined, `Długość klucza: ${key.length * 4} bitów`);
    let result: string;
    if (this.mode === 'ECB') {
      result = this.decryptECB(ciphertext, key);
    } else if (this.mode === 'CBC') {
      result = this.decryptCBC(ciphertext, key);
    } else if (this.mode === 'CTR') {
      result = this.decryptCTR(ciphertext, key);
    } else {
      throw new Error(`Tryb ${this.mode} nie jest obsługiwany`);
    }
    this.logStep('Zakończenie deszyfrowania AES', ciphertext, result);
    return result;
  }

  // ========================================================================
  // TRYB ECB (Electronic Codebook)
  // ========================================================================

  private encryptECB(plaintext: string, key: string): string {
    this.logStep('ECB: Rozpoczęcie trybu Electronic Codebook', plaintext, undefined, 'Tryb ECB - najprostszy tryb AES. Każdy blok 16 bajtów jest szyfrowany osobno tym samym kluczem. UWAGA: Ten sam tekst zawsze da ten sam szyfrogram (niebezpieczne dla powtarzających się danych).');
    
    // Konwertuj tekst do bajtów UTF-8
    const plaintextBytes = this.stringToBytes(plaintext);
    this.logStep('ECB: Konwersja tekstu na bajty', plaintext, undefined, `Tekst zamieniony na liczby (bajty) używając kodowania UTF-8. Każdy znak to 1-4 bajty. Wynik: ${plaintextBytes.length} bajtów. AES operuje na bajtach, nie na literach.`);
    
    // Dodaj padding PKCS#7
    const paddedBytes = this.addPadding(plaintextBytes);
    const paddingAdded = paddedBytes.length - plaintextBytes.length;
    this.logStep(
      'ECB: Dodanie paddingu PKCS#7',
      `${plaintextBytes.length} bajtów`,
      `${paddedBytes.length} bajtów`,
      `AES wymaga, aby dane były wielokrotnością 16 bajtów. Dodano ${paddingAdded} bajtów wypełnienia, każdy o wartości ${paddingAdded} (standard PKCS#7). Dzięki temu możemy później rozpoznać i usunąć padding.`
    );
    
    // Konwertuj klucz hex na bajty
    const keyBytes = this.hexToBytes(key);
    this.logStep('ECB: Konwersja klucza', key, undefined, `Klucz w formacie szesnastkowym (HEX) zamieniony na bajty. Długość: ${keyBytes.length * 8} bitów = ${keyBytes.length} bajtów. To jest AES-${keyBytes.length * 8} (im dłuższy klucz, tym bezpieczniejsze szyfrowanie).`);
    
    // Rozwiń klucz
    const expandedKey = this.keyExpansion(keyBytes);
    const rounds = expandedKey.length / 16 - 1;
    this.logStep(
      'ECB: Ekspansja klucza',
      undefined,
      undefined,
      `Z oryginalnego klucza wygenerowano ${rounds} kluczy rundowych (jeden dla każdej rundy szyfrowania). Każdy blok przechodzi przez ${rounds} rund transformacji, używając za każdym razem innego klucza. Łącznie: ${expandedKey.length} bajtów kluczy.`
    );
    
    // Szyfruj bloki
    const numBlocks = paddedBytes.length / 16;
    this.logStep('ECB: Początek szyfrowania bloków', undefined, undefined, `Dane podzielone na ${numBlocks} bloków po 16 bajtów każdy. Teraz każdy blok zostanie osobno zaszyfrowany przez AES. W trybie ECB bloki są niezależne - szyfrowanie jednego nie wpływa na inne.`);
    
    const cipherBytes: number[] = [];
    for (let i = 0; i < paddedBytes.length; i += 16) {
      const blockNum = (i / 16) + 1;
      const block = paddedBytes.slice(i, i + 16);
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `ECB: Szyfrowanie bloku ${blockNum}/${numBlocks}`,
          this.bytesToHex(block),
          undefined,
          `Blok ${blockNum} (16 bajtów w formacie HEX) jest przetwarzany. Przechodzi przez ${rounds} rund, w każdej: SubBytes (zamiana bajtów przez S-Box), ShiftRows (przesunięcie wierszy), MixColumns (mieszanie kolumn), AddRoundKey (XOR z kluczem rundowym).`
        );
      }
      
      const encryptedBlock = this.encryptBlock(block, expandedKey);
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `ECB: Blok ${blockNum} zaszyfrowany`,
          this.bytesToHex(block),
          this.bytesToHex(encryptedBlock),
          `Blok ${blockNum} po przejściu przez wszystkie ${rounds} rund AES. Dane są teraz całkowicie przekształcone i nieczytelne. Bez klucza nie da się ich odzyskać. Porównaj: oryginalny blok → zaszyfrowany blok (oba w HEX).`
        );
      }
      
      cipherBytes.push(...encryptedBlock);
    }
    
    if (numBlocks > 3) {
      this.logStep('ECB: Pominięto szczegóły środkowych bloków', undefined, undefined, `Zaszyfrowano ${numBlocks - 3} bloków środkowych (bloki 3-${numBlocks-1}) tym samym procesem. Aby skrócić logi, pokazano tylko pierwsze 2 i ostatni blok.`);
    }
    
    // Konwertuj na hex
    const result = this.bytesToHex(cipherBytes);
    this.logStep('ECB: Konwersja wyniku na hex', undefined, result, `Wszystkie zaszyfrowane bajty zamienione na format szesnastkowy (HEX) - łatwiejszy do odczytu i przechowywania. Długość: ${result.length} znaków HEX = ${result.length/2} bajtów. To jest finalny szyfrogram!`);
    return result;
  }

  private decryptECB(ciphertext: string, key: string): string {
    try {
      this.logStep('ECB: Rozpoczęcie deszyfrowania', ciphertext, undefined, 'Tryb Electronic Codebook - deszyfrowanie. Proces odwrotny do szyfrowania. Każdy 16-bajtowy blok będzie niezależnie odszyfrowany tym samym kluczem.');
      
      // Konwertuj hex na bajty
      const cipherBytes = this.hexToBytes(ciphertext);
      this.logStep('ECB: Konwersja hex na bajty', ciphertext.substring(0, 32) + '...', undefined, `Szyfrogram w formacie HEX zamieniamy z powrotem na bajty (liczby 0-255). Długość: ${cipherBytes.length} bajtów. AES operuje na bajtach, więc musimy przekonwertować tekst HEX.`);
      
      // Sprawdź czy długość jest wielokrotnością 16
      if (cipherBytes.length % 16 !== 0) {
        throw new Error('Nieprawidłowa długość szyfrogramu');
      }
      
      const numBlocks = cipherBytes.length / 16;
      this.logStep('ECB: Weryfikacja bloków', undefined, undefined, `Sprawdzenie poprawności danych. Szyfrogram ma ${numBlocks} bloków po 16 bajtów. Jeśli długość nie jest wielokrotnością 16, dane są uszkodzone lub nieprawidłowe.`);
      
      // Konwertuj klucz hex na bajty
      const keyBytes = this.hexToBytes(key);
      
      // Rozwiń klucz
      const expandedKey = this.keyExpansion(keyBytes);
      const rounds = expandedKey.length / 16 - 1;
      this.logStep('ECB: Ekspansja klucza deszyfrowania', undefined, undefined, `Generujemy te same klucze rundowe co przy szyfrowaniu (${rounds} kluczy), ale przy deszyfrowaniu używamy ich w odwrotnej kolejności i stosujemy odwrotne operacje (InvSubBytes, InvShiftRows, InvMixColumns).`);
      
      // Deszyfruj bloki
      const plaintextBytes: number[] = [];
      for (let i = 0; i < cipherBytes.length; i += 16) {
        const blockNum = (i / 16) + 1;
        const block = cipherBytes.slice(i, i + 16);
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `ECB: Deszyfrowanie bloku ${blockNum}/${numBlocks}`,
            this.bytesToHex(block),
            undefined,
            `Blok ${blockNum} jest odszyfrowywany. Każda runda stosuje ODWROTNE operacje: InvSubBytes (odwrotny S-Box), InvShiftRows (odwrotne przesunięcie), InvMixColumns (odwrotne mieszanie), a na końcu XOR z kluczem. Dzięki temu odzyskujemy oryginalny tekst.`
          );
        }
        
        const decryptedBlock = this.decryptBlock(block, expandedKey);
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `ECB: Blok ${blockNum} odszyfrowany`,
            this.bytesToHex(block),
            this.bytesToHex(decryptedBlock),
            'Przywrócono oryginalną zawartość bloku'
          );
        }
        
        plaintextBytes.push(...decryptedBlock);
      }
      
      if (numBlocks > 3) {
        this.logStep('ECB: Pominięto szczegóły środkowych bloków', undefined, undefined, `Odszyfrowano ${numBlocks - 3} bloków środkowych (bloki 3-${numBlocks-1}) tym samym procesem. Pokazano tylko pierwsze 2 i ostatni blok dla zwięzłości logów.`);
      }
      
      // Usuń padding
      const paddingValue = plaintextBytes[plaintextBytes.length - 1];
      this.logStep(
        'ECB: Usuwanie paddingu PKCS#7',
        `${plaintextBytes.length} bajtów`,
        `${plaintextBytes.length - paddingValue} bajtów`,
        `Ostatni bajt ma wartość ${paddingValue}, co oznacza że ostatnie ${paddingValue} bajtów to padding (sztuczne wypełnienie dodane przy szyfrowaniu). Usuwamy go, aby odzyskać oryginalną długość danych. PKCS#7: wartość paddingu = liczba bajtów paddingu.`
      );
      const unpaddedBytes = this.removePadding(plaintextBytes);
      
      // Konwertuj na string
      const result = this.bytesToString(unpaddedBytes);
      this.logStep('ECB: Konwersja bajtów na tekst', undefined, result, `Ostatni krok: bajty (liczby) zamieniamy z powrotem na tekst używając kodowania UTF-8. Każda liczba odpowiada określonemu znakowi. Odzyskaliśmy ORYGINALNY TEKST spłed przed szyfrowania!`);
      return result;
    } catch (error) {
      throw new Error(`Błąd deszyfrowania: ${error}`);
    }
  }

  // ========================================================================
  // TRYB CBC (Cipher Block Chaining)
  // ========================================================================

  private encryptCBC(plaintext: string, key: string): string {
    this.logStep('CBC: Rozpoczęcie trybu Cipher Block Chaining', plaintext, undefined, 'Tryb CBC - bezpieczniejszy niż ECB! Każdy blok przed szyfrowaniem jest XOR-owany z poprzednim zaszyfrowanym blokiem. Dzięki temu identyczne bloki dają różne szyfrogramy. Pierwszy blok używa IV (losowego wektora).');
    
    // Konwertuj tekst do bajtów UTF-8
    const plaintextBytes = this.stringToBytes(plaintext);
    this.logStep('CBC: Konwersja tekstu na bajty', plaintext, undefined, `Tekst zamieniony na ${plaintextBytes.length} bajtów (liczb 0-255) używając kodowania UTF-8. AES operuje na bajtach, nie na znakach.`);
    
    // Dodaj padding PKCS#7
    const paddedBytes = this.addPadding(plaintextBytes);
    const paddingAdded = paddedBytes.length - plaintextBytes.length;
    this.logStep('CBC: Dodanie paddingu PKCS#7', `${plaintextBytes.length} bajtów`, `${paddedBytes.length} bajtów`, `Dopóki długość nie jest wielokrotnością 16, dodajemy bajty wypełnienia. Dodano ${paddingAdded} bajtów, każdy o wartości ${paddingAdded} (PKCS#7). Łatwo je później rozpoznać i usunąć.`);
    
    // Konwertuj klucz hex na bajty
    const keyBytes = this.hexToBytes(key);
    
    // Rozwiń klucz
    const expandedKey = this.keyExpansion(keyBytes);
    const rounds = expandedKey.length / 16 - 1;
    this.logStep('CBC: Ekspansja klucza', undefined, undefined, `Z jednego klucza generujemy ${rounds} kluczy rundowych. Każdy blok przejdzie przez ${rounds} rund transformacji AES. Klucze rundowe są obliczane raz i używane dla wszystkich bloków.`);
    
    // Generuj losowy IV (Initialization Vector) - 16 bajtów
    const iv = this.generateRandomBytes(16);
    this.logStep('CBC: Generowanie IV (Initialization Vector)', undefined, this.bytesToHex(iv), 'IV to losowy 16-bajtowy ciąg używany do zaszyfrowania pierwszego bloku. Dzięki IV ten sam tekst da inny szyfrogram za każdym razem! IV nie jest tajny - będzie dołączony do szyfrogramu.');
    
    // Szyfruj bloki z użyciem CBC
    const numBlocks = paddedBytes.length / 16;
    this.logStep('CBC: Początek szyfrowania bloków', undefined, undefined, `${numBlocks} bloków do zaszyfrowania. W trybie CBC każdy blok zależy od poprzedniego - tworzy się łańcuch (Chain). Blok N jest XOR-owany z zaszyfrowanym blokiem N-1 przed własnym szyfrowaniem.`);
    
    const cipherBytes: number[] = [];
    let previousBlock = iv;
    
    for (let i = 0; i < paddedBytes.length; i += 16) {
      const blockNum = (i / 16) + 1;
      const block = paddedBytes.slice(i, i + 16);
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `CBC: Blok ${blockNum}/${numBlocks} - XOR z poprzednim`,
          this.bytesToHex(block),
          undefined,
          blockNum === 1 
            ? 'Blok 1: XOR z IV (wektorem inicjalizacyjnym). Każdy bajt bloku jest XOR-owany z odpowiednim bajtem IV. XOR = operacja bitowa: 0⊕1=1, 1⊕1=0, 0⊕0=0, 1⊕0=1.' 
            : `Blok ${blockNum}: XOR z poprzednim ZASZYFROWANYM blokiem (blok ${blockNum-1}). To tworzy zależność między blokami - główna zaleta CBC!`
        );
      }
      
      // XOR z poprzednim blokiem zaszyfrowanym (lub IV dla pierwszego bloku)
      const xoredBlock = this.xorBlocks(block, previousBlock);
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `CBC: Blok ${blockNum} po XOR`,
          this.bytesToHex(block),
          this.bytesToHex(xoredBlock),
          `Wynik operacji XOR: oryginalny blok ⊕ poprzedni = nowy blok. Te dane (już pomieszane z poprzednim blokiem) idą teraz do szyfrowania AES. Dzięki temu identyczne bloki tekstu dają różne szyfrogramy!`
        );
      }
      
      // Szyfruj blok
      const encryptedBlock = this.encryptBlock(xoredBlock, expandedKey);
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `CBC: Blok ${blockNum} zaszyfrowany`,
          this.bytesToHex(xoredBlock),
          this.bytesToHex(encryptedBlock),
          `Blok po XOR przeszedł przez wszystkie rundy AES. Teraz jest całkowicie zaszyfrowany. Ten zaszyfrowany blok będzie użyty do XOR-owania NASTĘPNEGO bloku - to właśnie tworzy łańcuch (Chaining) w CBC!`
        );
      }
      
      cipherBytes.push(...encryptedBlock);
      
      // Zapisz zaszyfrowany blok jako poprzedni
      previousBlock = encryptedBlock;
    }
    
    if (numBlocks > 3) {
      this.logStep('CBC: Pominięto szczegóły środkowych bloków', undefined, undefined, `Zaszyfrowano ${numBlocks - 3} bloków środkowych (bloki 3-${numBlocks-1}) identycznym procesem: XOR z poprzednim → szyfrowanie AES → użycie jako wejście dla następnego. Pokazano tylko kluczowe bloki dla zwięzłości.`);
    }
    
    // Zwróć IV + zaszyfrowane dane (IV jest potrzebny do deszyfrowania)
    const result = this.bytesToHex([...iv, ...cipherBytes]);
    this.logStep('CBC: Dołączenie IV do wyniku', undefined, result.substring(0, 32) + '...', `IV (pierwsze 16 bajtów) + zaszyfrowane bloki. IV MUSI być dołączony, bo bez niego nie da się odszyfować pierwszego bloku! IV nie jest tajny - może być jawny. Format: wszystko w HEX (${result.length} znaków).`);
    return result;
  }

  private decryptCBC(ciphertext: string, key: string): string {
    try {
      this.logStep('CBC: Rozpoczęcie deszyfrowania', ciphertext.substring(0, 32) + '...', undefined, 'Tryb Cipher Block Chaining - deszyfrowanie. Proces odwrotny: każdy blok deszyfrujemy AES, potem XOR z poprzednim zaszyfrowanym blokiem. Pierwszy blok używa IV.');
      
      // Konwertuj hex na bajty
      const allBytes = this.hexToBytes(ciphertext);
      
      // Pierwszy blok to IV
      if (allBytes.length < 32) { // Minimum: 16 bajtów IV + 16 bajtów danych
        throw new Error('Nieprawidłowa długość szyfrogramu');
      }
      
      const iv = allBytes.slice(0, 16);
      this.logStep('CBC: Wyodrębnienie IV', undefined, this.bytesToHex(iv), 'Pierwsze 16 bajtów to wektor inicjalizacyjny');
      
      const cipherBytes = allBytes.slice(16);
      this.logStep('CBC: Wyodrębnienie zaszyfrowanych danych', undefined, undefined, `${cipherBytes.length} bajtów do odszyfrowania`);
      
      // Sprawdź czy długość danych jest wielokrotnością 16
      if (cipherBytes.length % 16 !== 0) {
        throw new Error('Nieprawidłowa długość szyfrogramu');
      }
      
      const numBlocks = cipherBytes.length / 16;
      this.logStep('CBC: Weryfikacja bloków', undefined, undefined, `${numBlocks} bloków 16-bajtowych`);
      
      // Konwertuj klucz hex na bajty
      const keyBytes = this.hexToBytes(key);
      
      // Rozwiń klucz
      const expandedKey = this.keyExpansion(keyBytes);
      const rounds = expandedKey.length / 16 - 1;
      this.logStep('CBC: Ekspansja klucza deszyfrowania', undefined, undefined, `${rounds} rund odwrotnych transformacji`);
      
      // Deszyfruj bloki z użyciem CBC
      this.logStep('CBC: Początek deszyfrowania bloków', undefined, undefined, `${numBlocks} bloków do odszyfrowania`);
      const plaintextBytes: number[] = [];
      let previousBlock = iv;
      
      for (let i = 0; i < cipherBytes.length; i += 16) {
        const blockNum = (i / 16) + 1;
        const block = cipherBytes.slice(i, i + 16);
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `CBC: Deszyfrowanie bloku ${blockNum}/${numBlocks}`,
            this.bytesToHex(block),
            undefined,
            'Odwrotne transformacje AES'
          );
        }
        
        // Deszyfruj blok
        const decryptedBlock = this.decryptBlock(block, expandedKey);
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `CBC: Blok ${blockNum} po odszyfrowaniu`,
            this.bytesToHex(block),
            this.bytesToHex(decryptedBlock),
            'Przed XOR z poprzednim'
          );
        }
        
        // XOR z poprzednim blokiem zaszyfrowanym (lub IV dla pierwszego bloku)
        const xoredBlock = this.xorBlocks(decryptedBlock, previousBlock);
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `CBC: Blok ${blockNum} po XOR`,
            this.bytesToHex(decryptedBlock),
            this.bytesToHex(xoredBlock),
            blockNum === 1 ? 'XOR z IV - przywrócono oryginalny tekst' : 'XOR z poprzednim zaszyfrowanym blokiem'
          );
        }
        
        plaintextBytes.push(...xoredBlock);
        
        // Zapisz zaszyfrowany blok jako poprzedni
        previousBlock = block;
      }
      
      if (numBlocks > 3) {
        this.logStep('CBC: Pominięto szczegóły', undefined, undefined, `Odszyfrowano ${numBlocks - 3} bloków środkowych`);
      }
      
      // Usuń padding
      const paddingValue = plaintextBytes[plaintextBytes.length - 1];
      this.logStep('CBC: Usuwanie paddingu PKCS#7', `${plaintextBytes.length} bajtów`, `${plaintextBytes.length - paddingValue} bajtów`, `Usunięto ${paddingValue} bajtów`);
      const unpaddedBytes = this.removePadding(plaintextBytes);
      
      // Konwertuj na string
      const result = this.bytesToString(unpaddedBytes);
      this.logStep('CBC: Konwersja bajtów na tekst', undefined, result, 'Przywrócono oryginalny tekst');
      return result;
    } catch (error) {
      throw new Error(`Błąd deszyfrowania CBC: ${error}`);
    }
  }

  // ========================================================================
  // TRYB CTR (Counter Mode)
  // ========================================================================

  private encryptCTR(plaintext: string, key: string): string {
    this.logStep('CTR: Rozpoczęcie trybu Counter Mode', plaintext, undefined, 'Tryb strumieniowy - szyfruje licznik i XOR z danymi');
    
    // Konwertuj tekst do bajtów UTF-8
    const plaintextBytes = this.stringToBytes(plaintext);
    this.logStep('CTR: Konwersja tekstu na bajty', plaintext, undefined, `Długość: ${plaintextBytes.length} bajtów (bez paddingu)`);
    
    // Konwertuj klucz hex na bajty
    const keyBytes = this.hexToBytes(key);
    
    // Rozwiń klucz
    const expandedKey = this.keyExpansion(keyBytes);
    const rounds = expandedKey.length / 16 - 1;
    this.logStep('CTR: Ekspansja klucza', undefined, undefined, `Generujemy ${rounds} kluczy rundowych z oryginalnego klucza. W trybie CTR NIE szyfrujemy danych bezpośrednio - szyfrujemy COUNTER, a potem XOR z danymi. To czyni CTR trybem strumieniowym!`);
    
    // Generuj losowy nonce - 8 bajtów (pozostałe 8 bajtów to counter)
    const nonce = this.generateRandomBytes(8);
    this.logStep('CTR: Generowanie nonce', undefined, this.bytesToHex(nonce), 'NONCE = Number used ONCE (liczba użyta raz). Losowe 8 bajtów. Do każdego nonce dodamy counter (licznik bloku), tworząc 16-bajtowy blok. Counter rośnie: 0, 1, 2... Dzięki temu każdy blok ma unikalny input.');
    
    // Szyfruj używając CTR
    const numBlocks = Math.ceil(plaintextBytes.length / 16);
    this.logStep('CTR: Obliczenie liczby bloków', undefined, undefined, `${numBlocks} bloków do przetworzenia. UWAGA: CTR nie wymaga paddingu! Ostatni blok może być krótszy niż 16 bajtów. To zaleta trybu strumieniowego.`);
    
    const cipherBytes: number[] = [];
    let counter = 0;
    
    for (let i = 0; i < plaintextBytes.length; i += 16) {
      const blockNum = counter + 1;
      
      // Przygotuj blok countera: nonce (8 bajtów) + counter (8 bajtów)
      const counterBlock = this.createCounterBlock(nonce, counter);
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `CTR: Blok ${blockNum}/${numBlocks} - przygotowanie countera`,
          undefined,
          this.bytesToHex(counterBlock),
          `Counter block = NONCE (8B, stały) + COUNTER (8B, wartość=${counter}). Każdy blok ma inny counter, więc inny input do AES. To zapewnia, że ten sam tekst da inny szyfrogram za każdym razem (dzięki losowemu nonce).`
        );
      }
      
      // Szyfruj blok countera
      const encryptedCounter = this.encryptBlock(counterBlock, expandedKey);
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `CTR: Blok ${blockNum} - szyfrowanie countera`,
          this.bytesToHex(counterBlock),
          this.bytesToHex(encryptedCounter),
          `Counter block przeszedł przez AES. Wynik to KEYSTREAM (strumień klucza) - 16 pseudolosowych bajtów. NIE szyfrujemy danych - szyfrujemy COUNTER! Keystream posłuży do XOR z danymi.`
        );
      }
      
      // Pobierz blok danych (może być mniejszy niż 16 bajtów dla ostatniego bloku)
      const blockSize = Math.min(16, plaintextBytes.length - i);
      const dataBlock = plaintextBytes.slice(i, i + blockSize);
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `CTR: Blok ${blockNum} - dane do zaszyfrowania`,
          this.bytesToHex(dataBlock),
          undefined,
          `${blockSize} bajtów danych oryginalnych. Teraz zrobimy prostą operację: każdy bajt danych XOR odpowiadający bajt keystream. XOR jest symetryczny: A⊕B=C, więc C⊕B=A. To pozwala użyć tej samej operacji do szyfrowania i deszyfrowania!`
        );
      }
      
      // XOR danych z zaszyfrowanym counterem
      const encryptedData: number[] = [];
      for (let j = 0; j < blockSize; j++) {
        encryptedData.push(dataBlock[j] ^ encryptedCounter[j]);
        cipherBytes.push(dataBlock[j] ^ encryptedCounter[j]);
      }
      
      if (blockNum <= 2 || blockNum === numBlocks) {
        this.logStep(
          `CTR: Blok ${blockNum} zaszyfrowany`,
          this.bytesToHex(dataBlock),
          this.bytesToHex(encryptedData),
          `Operacja: dane ⊕ keystream = szyfrogram. Każdy bajt danych XOR z odpowiadającym bajtem keystream. Wynik: zaszyfrowane dane! Prosty i szybki tryb, równoległy (każdy blok niezależny), bez paddingu.`
        );
      }
      
      counter++;
    }
    
    if (numBlocks > 3) {
      this.logStep('CTR: Pominięto szczegóły środkowych bloków', undefined, undefined, `Przetworzono ${numBlocks - 3} bloków środkowych (bloki 3-${numBlocks-1}). Każdy: counter+${3} do counter+${numBlocks-2}, szyfrowanie countera, XOR z danymi. Proces identyczny dla każdego bloku.`);
    }
    
    // Zwróć nonce + zaszyfrowane dane
    const result = this.bytesToHex([...nonce, ...cipherBytes]);
    this.logStep('CTR: Dołączenie nonce do wyniku', undefined, result.substring(0, 32) + '...', `NONCE (8B) + zaszyfrowane dane. Nonce jest potrzebny do deszyfrowania - bez niego nie wygenerujemy tych samych keystreamów! Nonce nie jest tajny. Długość HEX: ${result.length} znaków.`);
    return result;
  }

  private decryptCTR(ciphertext: string, key: string): string {
    try {
      this.logStep('CTR: Rozpoczęcie deszyfrowania', ciphertext.substring(0, 32) + '...', undefined, 'W trybie CTR deszyfrowanie = szyfrowanie! To magia XOR: jeśli A⊕B=C, to C⊕B=A. Zaszyfrowane dane ⊕ ten sam keystream = oryginalny tekst. Używamy tego samego nonce i counterów.');
      
      // W trybie CTR szyfrowanie i deszyfrowanie to ta sama operacja
      // Konwertuj hex na bajty
      const allBytes = this.hexToBytes(ciphertext);
      
      // Pierwsze 8 bajtów to nonce
      if (allBytes.length < 9) {
        throw new Error('Nieprawidłowa długość szyfrogramu');
      }
      
      const nonce = allBytes.slice(0, 8);
      this.logStep('CTR: Wyodrębnienie nonce', undefined, this.bytesToHex(nonce), 'Pierwsze 8 bajtów szyfrogramu to nonce (ten sam co użyty przy szyfrowaniu). Nonce + counter pozwolą wygenerować IDENTYCZNE keystreamy jak przy szyfrowaniu.');
      
      const cipherBytes = allBytes.slice(8);
      this.logStep('CTR: Wyodrębnienie zaszyfrowanych danych', undefined, undefined, `${cipherBytes.length} bajtów do odszyfrowania`);
      
      // Konwertuj klucz hex na bajty
      const keyBytes = this.hexToBytes(key);
      
      // Rozwiń klucz
      const expandedKey = this.keyExpansion(keyBytes);
      const rounds = expandedKey.length / 16 - 1;
      this.logStep('CTR: Ekspansja klucza', undefined, undefined, `${rounds} rund transformacji (identyczne jak przy szyfrowaniu)`);
      
      // Deszyfruj używając CTR (identyczna operacja jak szyfrowanie)
      const numBlocks = Math.ceil(cipherBytes.length / 16);
      this.logStep('CTR: Obliczenie liczby bloków', undefined, undefined, `${numBlocks} bloków do przetworzenia`);
      
      const plaintextBytes: number[] = [];
      let counter = 0;
      
      for (let i = 0; i < cipherBytes.length; i += 16) {
        const blockNum = counter + 1;
        
        // Przygotuj blok countera
        const counterBlock = this.createCounterBlock(nonce, counter);
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `CTR: Blok ${blockNum}/${numBlocks} - rekonstrukcja countera`,
            undefined,
            this.bytesToHex(counterBlock),
            `Ten sam nonce + Counter(${counter})`
          );
        }
        
        // Szyfruj blok countera
        const encryptedCounter = this.encryptBlock(counterBlock, expandedKey);
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `CTR: Blok ${blockNum} - szyfrowanie countera`,
            this.bytesToHex(counterBlock),
            this.bytesToHex(encryptedCounter),
            'Wygenerowano ten sam keystream co przy szyfrowaniu'
          );
        }
        
        // Pobierz blok danych
        const blockSize = Math.min(16, cipherBytes.length - i);
        const dataBlock = cipherBytes.slice(i, i + blockSize);
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `CTR: Blok ${blockNum} - zaszyfrowane dane`,
            this.bytesToHex(dataBlock),
            undefined,
            `${blockSize} bajtów`
          );
        }
        
        // XOR danych z zaszyfrowanym counterem
        const decryptedData: number[] = [];
        for (let j = 0; j < blockSize; j++) {
          decryptedData.push(dataBlock[j] ^ encryptedCounter[j]);
          plaintextBytes.push(dataBlock[j] ^ encryptedCounter[j]);
        }
        
        if (blockNum <= 2 || blockNum === numBlocks) {
          this.logStep(
            `CTR: Blok ${blockNum} odszyfrowany`,
            this.bytesToHex(dataBlock),
            this.bytesToHex(decryptedData),
            'Zaszyfrowane dane XOR keystream = oryginalne dane'
          );
        }
        
        counter++;
      }
      
      if (numBlocks > 3) {
        this.logStep('CTR: Pominięto szczegóły', undefined, undefined, `Przetworzono ${numBlocks - 3} bloków środkowych`);
      }
      
      // Konwertuj na string (bez usuwania paddingu - CTR nie używa paddingu)
      const result = this.bytesToString(plaintextBytes);
      this.logStep('CTR: Konwersja bajtów na tekst', undefined, result, 'Przywrócono oryginalny tekst (bez paddingu)');
      return result;
    } catch (error) {
      throw new Error(`Błąd deszyfrowania CTR: ${error}`);
    }
  }

  // ========================================================================
  // PODSTAWOWE OPERACJE AES
  // ========================================================================

  private encryptBlock(block: number[], expandedKey: number[][]): number[] {
    const state = this.arrayToState(block);
    const nRounds = expandedKey.length - 1;

    // Początkowa runda
    this.addRoundKey(state, expandedKey[0]);

    // Rundy główne
    for (let round = 1; round < nRounds; round++) {
      this.subBytes(state);
      this.shiftRows(state);
      this.mixColumns(state);
      this.addRoundKey(state, expandedKey[round]);
    }

    // Ostatnia runda (bez MixColumns)
    this.subBytes(state);
    this.shiftRows(state);
    this.addRoundKey(state, expandedKey[nRounds]);

    return this.stateToArray(state);
  }

  private decryptBlock(block: number[], expandedKey: number[][]): number[] {
    const state = this.arrayToState(block);
    const nRounds = expandedKey.length - 1;

    // Początkowa runda
    this.addRoundKey(state, expandedKey[nRounds]);

    // Rundy główne (w odwrotnej kolejności)
    for (let round = nRounds - 1; round > 0; round--) {
      this.invShiftRows(state);
      this.invSubBytes(state);
      this.addRoundKey(state, expandedKey[round]);
      this.invMixColumns(state);
    }

    // Ostatnia runda (bez InvMixColumns)
    this.invShiftRows(state);
    this.invSubBytes(state);
    this.addRoundKey(state, expandedKey[0]);

    return this.stateToArray(state);
  }

  // ========================================================================
  // TRANSFORMACJE AES
  // ========================================================================

  private subBytes(state: number[][]): void {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] = SBOX[state[i][j]];
      }
    }
  }

  private invSubBytes(state: number[][]): void {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] = INV_SBOX[state[i][j]];
      }
    }
  }

  private shiftRows(state: number[][]): void {
    // Wiersz 0: bez przesunięcia
    // Wiersz 1: przesunięcie o 1 w lewo
    let temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Wiersz 2: przesunięcie o 2 w lewo
    temp = state[2][0];
    let temp2 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = temp;
    state[2][3] = temp2;

    // Wiersz 3: przesunięcie o 3 w lewo (lub 1 w prawo)
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
  }

  private invShiftRows(state: number[][]): void {
    // Wiersz 0: bez przesunięcia
    // Wiersz 1: przesunięcie o 1 w prawo
    let temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Wiersz 2: przesunięcie o 2 w prawo
    temp = state[2][3];
    let temp2 = state[2][2];
    state[2][3] = state[2][1];
    state[2][2] = state[2][0];
    state[2][1] = temp;
    state[2][0] = temp2;

    // Wiersz 3: przesunięcie o 3 w prawo (lub 1 w lewo)
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
  }

  private mixColumns(state: number[][]): void {
    for (let c = 0; c < 4; c++) {
      const s0 = state[0][c];
      const s1 = state[1][c];
      const s2 = state[2][c];
      const s3 = state[3][c];

      state[0][c] = this.gmul(s0, 2) ^ this.gmul(s1, 3) ^ s2 ^ s3;
      state[1][c] = s0 ^ this.gmul(s1, 2) ^ this.gmul(s2, 3) ^ s3;
      state[2][c] = s0 ^ s1 ^ this.gmul(s2, 2) ^ this.gmul(s3, 3);
      state[3][c] = this.gmul(s0, 3) ^ s1 ^ s2 ^ this.gmul(s3, 2);
    }
  }

  private invMixColumns(state: number[][]): void {
    for (let c = 0; c < 4; c++) {
      const s0 = state[0][c];
      const s1 = state[1][c];
      const s2 = state[2][c];
      const s3 = state[3][c];

      state[0][c] = this.gmul(s0, 14) ^ this.gmul(s1, 11) ^ this.gmul(s2, 13) ^ this.gmul(s3, 9);
      state[1][c] = this.gmul(s0, 9) ^ this.gmul(s1, 14) ^ this.gmul(s2, 11) ^ this.gmul(s3, 13);
      state[2][c] = this.gmul(s0, 13) ^ this.gmul(s1, 9) ^ this.gmul(s2, 14) ^ this.gmul(s3, 11);
      state[3][c] = this.gmul(s0, 11) ^ this.gmul(s1, 13) ^ this.gmul(s2, 9) ^ this.gmul(s3, 14);
    }
  }

  private addRoundKey(state: number[][], roundKey: number[]): void {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] ^= roundKey[i * 4 + j];
      }
    }
  }

  // ========================================================================
  // MNOŻENIE W CIELE GALOISA GF(2^8)
  // ========================================================================

  private gmul(a: number, b: number): number {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) {
        p ^= a;
      }
      const hiBitSet = a & 0x80;
      a <<= 1;
      if (hiBitSet) {
        a ^= 0x1b; // Wielomian nieredukowalny x^8 + x^4 + x^3 + x + 1
      }
      b >>= 1;
    }
    return p & 0xFF;
  }

  // ========================================================================
  // ROZSZERZENIE KLUCZA (Key Expansion)
  // ========================================================================

  private keyExpansion(key: number[]): number[][] {
    const keyLength = key.length;
    const nRounds = keyLength === 16 ? 10 : keyLength === 24 ? 12 : 14;
    const expandedKeySize = 16 * (nRounds + 1);
    
    const expandedKey: number[] = [...key];
    let bytesGenerated = keyLength;
    let rconIteration = 1;

    while (bytesGenerated < expandedKeySize) {
      // Weź ostatnie 4 bajty
      const temp = expandedKey.slice(bytesGenerated - 4, bytesGenerated);

      // Co N słów (gdzie N = keyLength/4), zastosuj transformację
      if (bytesGenerated % keyLength === 0) {
        // RotWord
        const t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;

        // SubWord
        temp[0] = SBOX[temp[0]];
        temp[1] = SBOX[temp[1]];
        temp[2] = SBOX[temp[2]];
        temp[3] = SBOX[temp[3]];

        // XOR z Rcon
        temp[0] ^= RCON[rconIteration++];
      } else if (keyLength === 32 && bytesGenerated % keyLength === 16) {
        // Dla AES-256, dodatkowa transformacja SubWord
        temp[0] = SBOX[temp[0]];
        temp[1] = SBOX[temp[1]];
        temp[2] = SBOX[temp[2]];
        temp[3] = SBOX[temp[3]];
      }

      // XOR z odpowiednim słowem N pozycji wcześniej
      for (let i = 0; i < 4; i++) {
        expandedKey[bytesGenerated] = expandedKey[bytesGenerated - keyLength] ^ temp[i];
        bytesGenerated++;
      }
    }

    // Podziel na rundy
    const roundKeys: number[][] = [];
    for (let i = 0; i < expandedKey.length; i += 16) {
      roundKeys.push(expandedKey.slice(i, i + 16));
    }

    return roundKeys;
  }

  // ========================================================================
  // PADDING PKCS#7
  // ========================================================================

  private addPadding(data: number[]): number[] {
    const paddingLength = 16 - (data.length % 16);
    const padded = [...data];
    for (let i = 0; i < paddingLength; i++) {
      padded.push(paddingLength);
    }
    return padded;
  }

  private removePadding(data: number[]): number[] {
    if (data.length === 0) {
      throw new Error('Puste dane do usunięcia paddingu');
    }
    const paddingLength = data[data.length - 1];
    
    // Walidacja paddingu
    if (paddingLength < 1 || paddingLength > 16) {
      throw new Error('Nieprawidłowy padding');
    }
    
    for (let i = 0; i < paddingLength; i++) {
      if (data[data.length - 1 - i] !== paddingLength) {
        throw new Error('Nieprawidłowy padding');
      }
    }
    
    return data.slice(0, data.length - paddingLength);
  }

  // ========================================================================
  // FUNKCJE POMOCNICZE
  // ========================================================================

  // Generuj losowe bajty
  private generateRandomBytes(length: number): number[] {
    const bytes: number[] = [];
    for (let i = 0; i < length; i++) {
      bytes.push(Math.floor(Math.random() * 256));
    }
    return bytes;
  }

  // XOR dwóch bloków bajtów
  private xorBlocks(block1: number[], block2: number[]): number[] {
    const result: number[] = [];
    for (let i = 0; i < block1.length; i++) {
      result.push(block1[i] ^ block2[i]);
    }
    return result;
  }

  // Tworzenie bloku countera dla trybu CTR
  private createCounterBlock(nonce: number[], counter: number): number[] {
    const block: number[] = [...nonce];
    
    // Dodaj counter jako 8 bajtów (big-endian)
    for (let i = 7; i >= 0; i--) {
      block.push((counter >> (i * 8)) & 0xFF);
    }
    
    return block;
  }

  private arrayToState(array: number[]): number[][] {
    const state: number[][] = [[], [], [], []];
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] = array[i + 4 * j];
      }
    }
    return state;
  }

  private stateToArray(state: number[][]): number[] {
    const array: number[] = [];
    for (let j = 0; j < 4; j++) {
      for (let i = 0; i < 4; i++) {
        array.push(state[i][j]);
      }
    }
    return array;
  }

  private stringToBytes(str: string): number[] {
    const bytes: number[] = [];
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code < 128) {
        bytes.push(code);
      } else if (code < 2048) {
        bytes.push(0xC0 | (code >> 6));
        bytes.push(0x80 | (code & 0x3F));
      } else if (code < 65536) {
        bytes.push(0xE0 | (code >> 12));
        bytes.push(0x80 | ((code >> 6) & 0x3F));
        bytes.push(0x80 | (code & 0x3F));
      } else {
        bytes.push(0xF0 | (code >> 18));
        bytes.push(0x80 | ((code >> 12) & 0x3F));
        bytes.push(0x80 | ((code >> 6) & 0x3F));
        bytes.push(0x80 | (code & 0x3F));
      }
    }
    return bytes;
  }

  private bytesToString(bytes: number[]): string {
    let str = '';
    let i = 0;
    while (i < bytes.length) {
      const byte = bytes[i];
      if (byte < 128) {
        str += String.fromCharCode(byte);
        i++;
      } else if (byte < 224) {
        str += String.fromCharCode(((byte & 0x1F) << 6) | (bytes[i + 1] & 0x3F));
        i += 2;
      } else if (byte < 240) {
        str += String.fromCharCode(((byte & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F));
        i += 3;
      } else {
        const code = ((byte & 0x07) << 18) | ((bytes[i + 1] & 0x3F) << 12) | ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F);
        str += String.fromCharCode(code);
        i += 4;
      }
    }
    return str;
  }

  private hexToBytes(hex: string): number[] {
    const bytes: number[] = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
  }

  private bytesToHex(bytes: number[]): string {
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
