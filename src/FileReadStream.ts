import { Readable, ReadableOptions } from 'stream';
import { anyToBuffer } from './utils/anyToBuffer';

export interface FileReadStreamOptions extends ReadableOptions {
	chunkSize?: number;
}

// Most of the code originally from
// [filestream](https://github.com/DamonOehlman/filestream)

export class FileReadStream extends Readable {
	private file: File|null;
	private offset: number;
	private size: number;
	private chunkSize: number;
	private reader: FileReader|null;

	constructor(file: File, options: FileReadStreamOptions = {}) {
		super(options);

		this.offset = 0;
		this.file = file;
		this.size = file.size;
		this.chunkSize = options.chunkSize || Math.max(this.size / 1024, 1024 * 1024);

		this.reader = new FileReader();
	}

	// tslint:disable-next-line:function-name
	_read() {
		let endOffset = this.offset + this.chunkSize;
		if (endOffset > this.size) {
			endOffset = this.size;
		}

		if (this.offset === this.size) {
			this.destroy();
			this.push(null);
			return;
		}

		if (this.file === null || this.reader === null) {
			return;
		}

		this.reader.onload = () => {
			this.offset = endOffset;

			if (this.reader!.result === null) {
				this.push(null);
			} else {
				this.push(anyToBuffer(this.reader!.result!, 'utf8'));
			}
		};

		this.reader.onerror = () => {
			this.emit('error', this.reader!.error);
		};

		this.reader.readAsArrayBuffer(this.file.slice(this.offset, endOffset));
	}

	destroy() {
		this.file = null;
		if (this.reader) {
			this.reader.onload = null;
			this.reader.onerror = null;
			try { this.reader.abort(); } catch (e) {};
		}

		this.reader = null;
	}
}
