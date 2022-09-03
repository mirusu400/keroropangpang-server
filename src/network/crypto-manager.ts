import Long = require("long");

export class CryptoManager {
	private _private_key: Buffer = Buffer.from(this._public_key);

	constructor(private readonly _public_key: Buffer = Buffer.from([155, 61, 100, 92, 135, 18, 250, 175, 149, 63, 99, 83, 55, 114, 250, 207])) {}

	public get public_key(): Buffer {
		return this._public_key;
	}

	public get private_key(): Buffer {
		return this._private_key;
	}

	public set private_key(value: Buffer) {
		this._private_key = value;
	}

	public get_crypto_key(): Buffer {
		const key = Buffer.allocUnsafe(16);
		for (let i = 0; i < 16; i++) {
			key[i] = this._private_key[i] ^ this._public_key[i];
		}

		return key;
	}

	public crypt(data: Buffer): Buffer {
		const key = this.get_crypto_key();

		const a = -99 * data.length;
		let b = Long.fromNumber(2157);

		for (let i = 0; i < data.length; i++) {
			data[i] = Long.fromNumber(data[i])
				.xor(Long.fromNumber(a).and(0xff))
				.xor(b.shiftRight(8).and(0xff))
				.xor(key[i & 0xf])
				.and(0xff)
				.toNumber();
			b = b.mul(2171);
		}

		return data;
	}

	public static encrypt_header(buffer: Buffer) {
		const encrypted_header = Buffer.allocUnsafe(buffer.length);
		buffer.copy(encrypted_header);

		encrypted_header[0] = buffer[0];
		encrypted_header[1] = buffer[8];
		encrypted_header[2] = buffer[1];
		encrypted_header[3] = buffer[9];
		encrypted_header[4] = buffer[2];
		encrypted_header[5] = buffer[10];
		encrypted_header[6] = buffer[3];
		encrypted_header[7] = buffer[11];
		encrypted_header[8] = buffer[4];
		encrypted_header[9] = buffer[12];
		encrypted_header[10] = buffer[5];
		encrypted_header[11] = buffer[13];
		encrypted_header[12] = buffer[6];
		encrypted_header[13] = buffer[14];
		encrypted_header[14] = buffer[7];

		return encrypted_header;
	}

	public static decrypt_header(buffer: Buffer) {
		const decrypted_header = Buffer.allocUnsafe(buffer.length);
		buffer.copy(decrypted_header);

		decrypted_header[0] = buffer[0];
		decrypted_header[1] = buffer[2];
		decrypted_header[2] = buffer[4];
		decrypted_header[3] = buffer[6];
		decrypted_header[4] = buffer[8];
		decrypted_header[5] = buffer[10];
		decrypted_header[6] = buffer[12];
		decrypted_header[7] = buffer[14];
		decrypted_header[8] = buffer[1];
		decrypted_header[9] = buffer[3];
		decrypted_header[10] = buffer[5];
		decrypted_header[11] = buffer[7];
		decrypted_header[12] = buffer[9];
		decrypted_header[13] = buffer[11];
		decrypted_header[14] = buffer[13];

		return decrypted_header;
	}
}
