// ============================================================================
// ARCHITEKTURA: Strategy Pattern dla algorytmów kryptograficznych
// Wszystkie algorytmy implementowane są ręcznie, bez gotowych bibliotek
// ============================================================================

export default class CryptographicAlgorithm {
  name: string;
  description: string;
  category: string;

  constructor(name: string, description: string, category: string) {
    this.name = name;
    this.description = description;
    this.category = category;
  }

  encrypt(plaintext: string, key: string): string {
    throw new Error('Metoda encrypt() musi być zaimplementowana');
  }

  decrypt(ciphertext: string, key: string): string {
    throw new Error('Metoda decrypt() musi być zaimplementowana');
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    throw new Error('Metoda validateKey() musi być zaimplementowana');
  }

  getKeyRequirements(): string {
    throw new Error('Metoda getKeyRequirements() musi być zaimplementowana');
  }
}
