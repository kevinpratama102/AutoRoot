# INF8602-CVE-2020-8835

How to test

- Clone
- ```npm link``` in the cloned repo
- Create another folder outside of this repo
- In that newly created folder: ```npm link inf8602-cve-2020-8835```
- Create an index.js file in the newly created folder and add this:
```Javascript
const helloNpm = require('inf8602-cve-2020-8835')
console.log(helloNpm())
```
