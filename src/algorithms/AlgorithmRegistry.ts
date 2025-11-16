// ============================================================================
// REJESTR ALGORYTMÓW - Singleton Pattern
// ============================================================================

import CryptographicAlgorithm from './CryptographicAlgorithm';
import CaesarCipher from './CaesarCipher';
import VigenereCipher from './VigenereCipher';
import RunningKeyCipher from './RunningKeyCipher';
import AESCipher from './AESCipher';
import RSACipher from './RSACipher';

export interface AlgorithmInfo {
  id: string;
  name: string;
  description: string;
  category: string;
}

class AlgorithmRegistry {
  private static instance: AlgorithmRegistry;
  private algorithms: Map<string, CryptographicAlgorithm> = new Map();

  constructor() {
    if (AlgorithmRegistry.instance) {
      return AlgorithmRegistry.instance;
    }
    
    this.algorithms = new Map();
    this._registerDefaultAlgorithms();
    AlgorithmRegistry.instance = this;
  }

  private _registerDefaultAlgorithms() {
    this.register('caesar', new CaesarCipher());
    this.register('vigenere', new VigenereCipher());
    this.register('running-key', new RunningKeyCipher());
    this.register('aes', new AESCipher());
    this.register('rsa', new RSACipher());
  }

  register(id: string, algorithm: CryptographicAlgorithm) {
    this.algorithms.set(id, algorithm);
  }

  get(id: string): CryptographicAlgorithm | undefined {
    return this.algorithms.get(id);
  }

  getAll(): AlgorithmInfo[] {
    return Array.from(this.algorithms.entries()).map(([id, algo]) => ({
      id,
      name: algo.name,
      description: algo.description,
      category: algo.category
    }));
  }
}

export const registry = new AlgorithmRegistry();
