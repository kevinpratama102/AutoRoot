'use strict';

const express = require('express');

// Constants
const PORT = 8080;
const HOST = '0.0.0.0';

// App
const app = express();
app.get('/', (req, res) => {
    const helloNpm = require('inf8602-cve-2020-8835')
    res.send(helloNpm());
});

app.listen(PORT, HOST, () => {
  console.log(`Running on http://${HOST}:${PORT}`);
  const helloNpm = require('inf8602-cve-2020-8835')
  console.log(helloNpm())
});