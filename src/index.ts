import { CryptoManager } from './crypto/manager';
import { EncryptedStorage } from './storage/encrypted';

export interface StorageOptions {
  keyDerivation: 'pbkdf2' | 'argon2';
  iterations?: number;
  memory?: number;
  salt?: string;
}

export class SecureStorage {
  private crypto: CryptoManager;
  private storage: EncryptedStorage;

  constructor(options: StorageOptions = { keyDerivation: 'pbkdf2' }) {
    this.crypto = new CryptoManager(options);
    this.storage = new EncryptedStorage(this.crypto);
  }

  async set(key: string, value: any): Promise<void> {
    const encrypted = await this.crypto.encrypt(JSON.stringify(value));
    await this.storage.set(key, encrypted);
  }

  async get<T>(key: string): Promise<T | null> {
    const encrypted = await this.storage.get(key);
    if (!encrypted) return null;
    
    try {
      const decrypted = await this.crypto.decrypt(encrypted);
      return JSON.parse(decrypted) as T;
    } catch {
      return null;
    }
  }

  async remove(key: string): Promise<void> {
    await this.storage.remove(key);
  }

  async clear(): Promise<void> {
    await this.storage.clear();
  }

  async keys(): Promise<string[]> {
    return this.storage.keys();
  }

  async has(key: string): Promise<boolean> {
    return this.storage.has(key);
  }

  async setPassword(password: string): Promise<void> {
    const salt = this.crypto.generateSalt();
    const key = await this.crypto.deriveKey(password, salt);
    await this.storage.set('_crypt_key', { key, salt });
  }

  async verifyPassword(password: string): Promise<boolean> {
    const stored = await this.storage.get<{ key: string; salt: string }>('_crypt_key');
    if (!stored) return false;
    
    const key = await this.crypto.deriveKey(password, stored.salt);
    return key === stored.key;
  }
}

export { CryptoManager, EncryptedStorage };
