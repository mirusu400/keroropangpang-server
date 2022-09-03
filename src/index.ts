import * as net from "net";
import { CryptoManager } from "./network";

net.createServer((socket) => {
	let globalBuffer = Buffer.allocUnsafe(0);
	let globalPacketLength = -1;
	const cryptoManager = new CryptoManager();

	const performPacket = (data: Buffer) => {
		globalBuffer = Buffer.concat([globalBuffer, data]);
		if (globalPacketLength < 0 && globalBuffer.length >= 56) globalPacketLength = CryptoManager.decrypt_header(globalBuffer).readUInt16LE(24);
		if (globalBuffer.length <= 0 || globalBuffer.length < globalPacketLength) return;

		const decrypted_data = cryptoManager.crypt(globalBuffer.slice(32, globalPacketLength));

		console.log(decrypted_data);

		const slicedPacket = globalBuffer.slice(globalPacketLength);
		globalBuffer = Buffer.allocUnsafe(0);
		globalPacketLength = -1;

		performPacket(slicedPacket);
	};

	socket.on("error", console.log);
	socket.on("data", performPacket.bind(this));
}).listen(18608, "0.0.0.0");
