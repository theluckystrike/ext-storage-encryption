export interface StorageOptions {
  keyDerivation: 'pbkdf2' | 'argon2';
  iterations?: number;
  memory?: number;
  salt?: string;
}

export class CryptoManager {
  private options: StorageOptions;
  private masterKey: CryptoKey | null = null;

  constructor(options: StorageOptions) {
    this.options = { iterations: 100000, memory: 65536, ...options };
  }

  generateSalt(): string {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    return this.arrayBufferToBase64(salt);
  }

  async deriveKey(password: string, salt: string): Promise<string> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const saltBuffer = this.base64ToArrayBuffer(salt);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: this.options.iterations || 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const exported = await crypto.subtle.exportKey('raw', key);
    return this.arrayBufferToBase64(new Uint8Array(exported));
  }

  async encrypt(plaintext: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.getOrCreateKey();

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return this.arrayBufferToBase64(combined);
  }

  async decrypt(ciphertext: string): Promise<string> {
    const decoder = new TextDecoder();
    const combined = this.base64ToArrayBuffer(ciphertext);
    const array = new Uint8Array(combined);

    const iv = array.slice(0, 12);
    const data = array.slice(12);

    const key = await this.getOrCreateKey();

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    return decoder.decode(decrypted);
  }

  private async getOrCreateKey(): Promise<CryptoKey> {
    if (this.masterKey) return this.masterKey;

    const stored = await chrome.storage.local.get('_ext_key');
    if (stored._ext_key) {
      const keyData = this.base64ToArrayBuffer(stored._ext_key);
      this.masterKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        'AES-GCM',
        false,
        ['encrypt', 'decrypt']
      );
      return this.masterKey;
    }

    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const exported = await crypto.subtle.exportKey('raw', key);
    await chrome.storage.local.set({
      _ext_key: this.arrayBufferToBase64(new Uint8Array(exported))
    });

    this.masterKey = key;
    return key;
  }

  private arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < buffer.byteLength; i++) {
      binary += String.fromCharCode(buffer[i]);
    }
    return btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
