'use strict'

const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();
const upload = multer({
  dest: 'uploads/'
});

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }

  res.send(`File uploaded: ${req.file.originalname}`);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
