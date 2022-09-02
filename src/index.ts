import net = require("net");
import Long = require("long");

const public_key = Buffer.from("9B 3D 64 5C 87 12 FA AF 95 3F 63 53 37 72 FA CF".split(" ").map((e) => parseInt(e, 16)));

function crypt(private_key: Buffer, data: Buffer) {
	let key = Buffer.allocUnsafe(16);
	for (let i = 0; i < 16; i++) {
		key[i] = private_key[i] ^ public_key[i];
	}

	let a = -99 * data.length;
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

function encrypt_header(buffer: Buffer) {
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

function decrypt_header(buffer: Buffer) {
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

function create_header(packet_length: number, v1: number, v2: number) {
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
	return encrypt_header(buffer);
}

function create_packet_header(sid: number, mid: number, result: number, packetID: number) {
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

function create_packet(header: Buffer, packet_header: Buffer, data: Buffer, privateKey: Buffer) {
	return Buffer.concat([header, crypt(privateKey, Buffer.concat([packet_header, data]))]);
}

interface KPPPacket {
	packetID: number;
	sid: number;
	mid: number;

	header: Buffer;
	packet_header: Buffer;
	packet_data: Buffer;
}

class KPPPacketHandler {
	constructor(private readonly _sid: number, private readonly _mid: number) {}

	public get sid(): number {
		return this._sid;
	}

	public get mid(): number {
		return this._mid;
	}

	public handle(packet: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {}
}

class KPPS100M11 extends KPPPacketHandler {
	constructor() {
		super(0x100, 0x11);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("GDMS LOGIN", ...arguments);
		const type = kppPacket.packet_data.slice(2, 5).toString();
		if (type !== "805") return;
		const tokenLen = kppPacket.packet_data.readUInt16LE(6);
		const token = kppPacket.packet_data.slice(40, 40 + tokenLen).toString();
		console.log("LOGIN, TOKEN:", token);

		const data = Buffer.allocUnsafe(32);
		data.set(manager.privateKey, 0);
		data.writeUint32LE(0, 16); // TODO: 분석필요
		data.writeUint32LE(0, 20); // TODO: 분석필요

		const someData = Buffer.allocUnsafe(8); // maybe session key
		for (let i = 0; i < someData.length; i++) someData[i] = i;
		data.set(someData, 24);

		let data1 = Buffer.allocUnsafe(0);

		const header = create_header(data1.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data1, public_key);

		socket.write(packet);
	}
}

class KPPS100M91 extends KPPPacketHandler {
	constructor() {
		super(0x100, 0x91);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("GDMS CHARINFO", ...arguments);

		const data = Buffer.allocUnsafe(392);

		data[0] = 0;
		data[1] = 1;
		data[2] = 2;
		data[3] = 3;
		data[4] = 4;
		data[5] = 5;
		data[6] = 6;
		data[7] = 7;
		data[8] = 8;

		for (let i = 9; i < data.length; i++) data[i] = i;

		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPS100M93 extends KPPPacketHandler {
	constructor() {
		super(0x100, 0x93);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("CREATE CHAR", ...arguments);

		const name = kppPacket.packet_data.slice(16, 32).toString().replace(/\0/g, "");
		const character = kppPacket.packet_data[50];

		console.log("name:", name, "character num:", character);

		const data = Buffer.allocUnsafe(56);

		data.writeUint32LE(1, 0); // maybe session key
		data.writeUint32LE(2, 4); // maybe session key

		data.writeUint32LE(3, 8);
		data.writeUint32LE(4, 12);

		data.set(new TextEncoder().encode(name), 16);

		data.writeUint32LE(5, 48);

		data.writeUint32LE(6, 52);

		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPS100M61 extends KPPPacketHandler {
	constructor() {
		super(0x100, 0x61);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("REQUEST SERVER LIST", ...arguments);

		const data = Buffer.allocUnsafe(68);
		for (let i = 0; i < data.length; i++) data[i] = 0;
		data.writeUInt32LE(2, 0);
		data.writeUInt32LE(0, 4);
		data.writeUInt32LE(1, 8); // 서버 이름
		data.writeUInt32LE(1, 16); // 서버 혼잡도???
		data.writeUInt32LE(0, 20); // ??

		// One Server Data Size = 32

		data.writeUInt32LE(2, 40); // 서버 이름
		data.writeUInt32LE(1, 44); // 서버 혼잡도???
		data.writeUInt32LE(2, 48); // ??

		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPS100M71 extends KPPPacketHandler {
	constructor() {
		super(0x100, 0x71);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("REQUEST CHANNEL LIST", ...arguments);

		const data = Buffer.allocUnsafe(528);
		for (let i = 0; i < data.length; i++) data[i] = 0;
		data.writeUInt32LE(kppPacket.packet_data.readUInt32LE(0), 0); // server id
		data.writeUInt32LE(0, 4);
		data.writeUInt32LE(3, 8); // channel no?
		data.writeUInt32LE(0, 12); // ???? 1이면 오류
		data.writeUInt32LE(1, 16); // channel 입장가능 여부?
		data.writeUInt32LE(4, 20); // channel type?
		data.writeUInt32LE(1, 24); // channel 혼잡도?

		data.writeUInt32LE(2, 72); // channel no?
		data.writeUInt32LE(0, 76); // ???? 1이면 오류
		data.writeUInt32LE(1, 80); // channel 입장가능 여부?
		data.writeUInt32LE(4, 84); // channel type?
		data.writeUInt32LE(1, 88); // channel 혼잡도?

		data.writeUInt32LE(3, 136); // channel no?
		data.writeUInt32LE(1, 140); // ???? 1이면 오류
		data.writeUInt32LE(1, 144); // channel 입장가능 여부?
		data.writeUInt32LE(8, 148); // channel type?
		data.writeUInt32LE(1, 152); // channel 혼잡도?
		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPS100M81 extends KPPPacketHandler {
	constructor() {
		super(0x100, 0x81);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("SELECT CHANNEL", ...arguments);

		const data = Buffer.allocUnsafe(16);
		data.writeUInt32LE(1, 0); // server
		data.writeUInt32LE(1, 4); // id
		data.writeUInt32LE(2130706433, 8); // ip to integer
		data.writeUInt16LE(57, 12);
		data.writeUInt16LE(18608, 12);
		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPS20M11 extends KPPPacketHandler {
	constructor() {
		super(0x20, 0x11);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("CSMS LOGIN", ...arguments);

		const data = Buffer.allocUnsafe(40);
		for (let i = 0; i < data.length; i++) data[i] = i;
		data.set(manager.privateKey, 0);

		const someData = Buffer.allocUnsafe(8); // maybe session key
		for (let i = 0; i < someData.length; i++) someData[i] = i;
		data.set(someData, 24);

		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPS200M17 extends KPPPacketHandler {
	constructor() {
		super(0x200, 0x17);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("SHOP ITEM LIST", ...arguments);

		const data = Buffer.allocUnsafe(1784);
		for (let i = 0; i < data.length; i++) data[i] = i;
		data.writeUInt32LE(1, 52);
		data.writeUInt32LE(0xffffffff, 68); // item code
		data.writeUInt32LE(0x0, 0xf);
		data.writeUInt32LE(0x0, 92);
		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPS20M6F extends KPPPacketHandler {
	constructor() {
		super(0x20, 0x6f);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("CSMS RANK", ...arguments);

		const data = Buffer.allocUnsafe(32);
		for (let i = 0; i < data.length; i++) data[i] = i;
		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPS20M71 extends KPPPacketHandler {
	constructor() {
		super(0x20, 0x71);
	}

	public handle(kppPacket: KPPPacket, socket: net.Socket, manager: KPPSocketManager): void {
		//TODO: 분석 필요
		console.log("CSMS CHAR INFO", ...arguments);

		const data = Buffer.allocUnsafe(400);
		for (let i = 0; i < data.length; i++) data[i] = i;
		const header = create_header(data.length + 56, 1, 1); // v1 and v2 must be 1
		const packet_header = create_packet_header(kppPacket.sid, kppPacket.mid + 1, 0, kppPacket.packetID);
		const packet = create_packet(header, packet_header, data, public_key);

		socket.write(packet);
	}
}

class KPPSocketManager {
	private readonly _map: Map<number, Map<number, KPPPacketHandler>> = new Map();
	public privateKey: Buffer = Buffer.allocUnsafe(16);

	constructor() {
		public_key.copy(this.privateKey);
	}

	public execute(kppPacket: KPPPacket, socket: net.Socket): void {
		const handler = this.get(kppPacket.sid, kppPacket.mid);

		if (handler) handler.handle.bind(handler)(kppPacket, socket, this);
		else console.log("Unknown Packet:", JSON.stringify(kppPacket, null, 2));
	}

	public get(sid: number, mid: number): KPPPacketHandler | null {
		const sidMap = this._map.get(sid);
		if (!sidMap) return null;

		const handler = sidMap.get(mid);
		if (!handler) return null;

		return handler;
	}

	public add(handler: KPPPacketHandler): void {
		const sid = handler.sid;
		const mid = handler.mid;

		if (!this._map.has(sid)) {
			this._map.set(sid, new Map());
		}

		const map = this._map.get(sid);
		map.set(mid, handler);
	}
}

net.createServer((socket) => {
	const manager = new KPPSocketManager();
	manager.add(new KPPS100M11());
	manager.add(new KPPS100M91());
	manager.add(new KPPS100M93());
	manager.add(new KPPS100M61());
	manager.add(new KPPS100M71());
	manager.add(new KPPS100M81());

	manager.add(new KPPS20M11());

	manager.add(new KPPS200M17());

	manager.add(new KPPS20M6F());

	manager.add(new KPPS20M71());

	let globalBuffer = Buffer.allocUnsafe(0);
	let globalPacketLength = -1;

	const performPacket = (data: Buffer) => {
		globalBuffer = Buffer.concat([globalBuffer, data]);
		if (globalPacketLength < 0 && globalBuffer.length >= 56) globalPacketLength = decrypt_header(globalBuffer).readUInt16LE(24);
		if (globalBuffer.length <= 0 || globalBuffer.length < globalPacketLength) return;

		const decrypted_data = crypt(manager.privateKey, globalBuffer.slice(32, globalPacketLength));

		const sid = decrypted_data.readUInt16LE(0);
		const mid = decrypted_data.readUInt16LE(2);
		const packetID = decrypted_data.readUInt16LE(4);

		const kppPacket: KPPPacket = {
			packetID,
			sid,
			mid,
			header: data.slice(0, 32),
			packet_header: decrypted_data.slice(0, 24),
			packet_data: decrypted_data.slice(24)
		};

		manager.execute(kppPacket, socket);

		const slicedPacket = globalBuffer.slice(globalPacketLength);
		globalBuffer = Buffer.allocUnsafe(0);
		globalPacketLength = -1;

		performPacket(slicedPacket);
	};

	socket.on("error", console.log);
	socket.on("data", performPacket.bind(this));
}).listen(18608, "0.0.0.0");
