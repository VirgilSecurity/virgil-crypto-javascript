if (!Symbol.asyncIterator) {
	(Symbol as any).asyncIterator = Symbol.for('Symbol.asyncIterator');
}

export async function* createAsyncIterable<T>(arr: T[]) {
	for (const item of arr) {
		yield item;
	}
}

export function readableStreamToPromise(readable: NodeJS.ReadableStream): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		readable.on('readable', () => {
			const data = readable.read();
			if (data) {
				chunks.push(data as Buffer);
			}
		});

		readable.on('error', err => {
			reject(err);
		});

		readable.on('end', () => {
			resolve(Buffer.concat(chunks));
		});
	});
}

export function writeToStreamInChunks(writable: NodeJS.WritableStream, input: Buffer) {
	const CHUNK_SIZE = 1024 * 1024; // 1Mb
	const inputChunks = splitIntoChunks(input, CHUNK_SIZE);

	function next() {
		if (inputChunks.length > 0) {
			writable.write(inputChunks.shift() as Buffer);
			setTimeout(next, 0);
		} else {
			writable.end();
		}
	}

	next();
}

export function splitIntoChunks (input: Buffer, chunkSize: number): Buffer[] {
	const chunks = [];
	let offset = 0;
	while(offset < input.byteLength) {
		chunks.push(input.slice(offset, offset += chunkSize));
	}
	return chunks;
}
