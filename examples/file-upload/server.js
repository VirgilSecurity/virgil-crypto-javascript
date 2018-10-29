const path = require('path');
const express = require('express');
const multer = require('multer');
// this middleware will handle the file uploads
// read more about it here - https://github.com/expressjs/multer
const upload = multer({ dest: 'uploads/' });

const app = express();

// sample database
const uploads = Object.create(null);

app.get('/', (req, res) => {
	res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/assets/virgil-crypto.browser.umd.js', (req, res) => {
	res.sendFile(path.join(__dirname, 'node_modules/virgil-crypto/dist/virgil-crypto.browser.umd.js'));
});

/**
 * File upload handler
 */
app.post('/uploads', upload.single('image'), (req, res) => {
	// req.file is the `image` file
	console.log(`Uploaded ${req.file.originalname}`);
	// save the uploaded file metadata to db
	uploads[req.file.filename] = req.file;
	const { originalname, filename, mimetype, size } = req.file;
	res.json({ originalname, filename, mimetype, size });
});

/**
 * File download handler
 */
app.get('/uploads/:filename', (req, res) => {
	const filename = req.params.filename;
	const descriptor = uploads[filename];
	if (!descriptor) {
		return res.status(404).send('File not found');
	}

	res.sendFile(path.join(__dirname, descriptor.path), err => {
		if (err) {
			console.log(err);
			next(err);
		} else {
			console.log(`Sent ${descriptor.originalname}`);
		}
	});
});

app.listen(3004, () => {
	console.log('server listening at port 3004...');
});
