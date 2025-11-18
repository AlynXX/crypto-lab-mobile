// ============================================================================
// ARCHITEKTURA: Strategy Pattern dla algorytmów kryptograficznych
// Wszystkie algorytmy implementowane są ręcznie, bez gotowych bibliotek
// ============================================================================

import logManager from '../utils/LogManager';

export default class CryptographicAlgorithm {
  name: string;
  description: string;
  category: string;
  protected enableLogging: boolean = true;

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

  /**
   * Dodaj krok do logu (jeśli logowanie jest włączone)
   */
  protected logStep(description: string, input?: string, output?: string, details?: string): void {
    if (this.enableLogging) {
      logManager.addStep(description, input, output, details);
    }
  }

  /**
   * Włącz/wyłącz logowanie dla algorytmu
   */
  setLogging(enabled: boolean): void {
    this.enableLogging = enabled;
  }
}
