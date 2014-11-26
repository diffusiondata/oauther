oauther
=======

Simple OAuth 1.0 signature generation/validation.

Supports HMAC-SHA1 and PLAINTEXT signatures.

Requirements
------------
- Express
- Node

Usage
-----

Initialise oauther with your secrets and use it to sign or validate requests.

```javascript
var oauther = require('oauther');

var oauth = oauther('consumer', 'token');

req = oauth.sign(req);

if (oauth.validate(req)) {
  console.log('Valid!');
}
```

Notes
-----
TODO: Clean up the tests. Add support for RSA-SHA1. Add support for plain Node.js http.
