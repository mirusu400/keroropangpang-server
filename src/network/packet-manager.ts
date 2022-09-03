import { CryptoManager } from "./crypto-manager";

export class PacketManager {
	public static create_header(packet_length: number, v1: number, v2: number) {
		const view = new DataView(new ArrayBuffer(32));
		//TODO: win32 timestamp
		const time = Date.now();

		view.setUint32(0, -0x7ed7d7d8, true);
		view.setUint32(4, 0x38121212, true);
		view.setUint32(8, time / 0xfa240, true);
		view.setUint32(12, time % 0xfa240, true);
		view.setUint32(16, 0, true);
		view.setUint32(20, 0, true);
		view.setUint32(24, packet_length, true);
		view.setUint32(26, v1, true);
		view.setUint32(27, v2, true);
		view.setUint16(28, 16, true);
		view.setUint16(30, 0, true);

		const buffer = Buffer.from(view.buffer);
		return CryptoManager.encrypt_header(buffer);
	}

	public static create_packet_header(sid: number, mid: number, result: number, packetID: number) {
		const view = new DataView(new ArrayBuffer(24));

		view.setUint16(0, sid, true);
		view.setUint16(2, mid, true);
		view.setUint16(4, packetID, true);
		view.setUint16(6, result, true);
		view.setUint32(8, 0, true); // unknown
		view.setUint32(12, 0, true); // unknown
		view.setUint32(16, 0, true); // unknown
		view.setUint16(20, 0, true); // unknown
		view.setUint16(22, 0, true); // unknown

		const buffer = Buffer.from(view.buffer);
		return buffer;
	}

	public static create_packet(header: Buffer, packet_header: Buffer, data: Buffer, crypto: CryptoManager) {
		return Buffer.concat([header, crypto.crypt(Buffer.concat([packet_header, data]))]);
	}
}
