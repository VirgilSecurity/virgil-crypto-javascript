import { Writable, WritableOptions } from 'stream';
import { anyToBuffer } from './utils/anyToBuffer';

export interface FileWriteStreamOptions extends WritableOptions {
	type?: string;
	name?: string;
}

export type FileCallback = (file: File) => void;

// Most of the code originally from
// [filestream](https://github.com/DamonOehlman/filestream)

export class FileWriteStream extends Writable {
	private buffers: any[];
	private bytesReceived: number;
	private callback: FileCallback;
	private type?: string;
	private name?: string;

	constructor (callback: FileCallback, options: FileWriteStreamOptions = {}) {
		const { type, name, ...opts } = options;
		super({ ...{ decodeStrings: false }, ...opts });

		this.on('finish', this.generateFile.bind(this));

		this.buffers = [];
		this.bytesReceived = 0;
		this.callback = callback;
		this.type = type;
		this.name = name;
	}

	private createFile() {
		if (this.buffers.length === 0) {
			return;
		}

		return new File(this.buffers, this.name || '', { type: this.type || '' });
	}

	private generateFile() {
		const file = this.createFile();
		if (file) {
			if (typeof this.callback === 'function') {
				this.callback(file);
			}

			this.emit('file', file);
		}

		this.buffers = [];
		this.bytesReceived = 0;
	}

	// tslint:disable-next-line:function-name
	_write(chunk: Buffer|string, encoding: string, callback: Function) {
		const data = Buffer.isBuffer(chunk) ? chunk : anyToBuffer(chunk, 'utf8');
		this.bytesReceived += data.length;
		this.buffers.push(data);
		this.emit('progress', this.bytesReceived);

		callback();
	}
}
