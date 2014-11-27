oauther
=======
[![Build Status](https://travis-ci.org/tommclaughlan/oauther.svg?branch=master)](https://travis-ci.org/tommclaughlan/oauther)

Simple OAuth 1.0 signature generation/validation.

Supports HMAC-SHA1 and PLAINTEXT signatures.

Requirements
------------
- Express
- Node

Installation
------------

```
npm install oauther
```

Usage
-----

Initialise oauther with your secrets and use it to sign or validate requests.

```javascript
var oauther = require('oauther');

var config = {
    consumer : { key : 'consumerkey', secret : 'consumersecret' },
    token : { key : 'tokenkey', secret : 'tokenkey' }, // optional
    signature_method : 'HMAC-SHA1', // 'HMAC-SHA1' (default), or 'PLAINTEXT'
    nonce_length : 32, // optional defaults to 32
    version : '1.0'  // currently only supports 1.0
};

var oauth = oauther(config);

var request = {
    hostname : 'example.com',
    path : '/oauther',
    method : 'GET'
};

var signature = oauth.sign(request);

// header formatted signature
req.header('Authorization', signature.toHeader());

// query formatted signature
var query = signature.toQuery();

...

// validate an incoming request
if (oauth.validate(req)) {
  console.log('Valid!');
}
```
Signing Requests
------

Request data needs to be passed to the sign method:
```
var request = {
    hostname : 'example.com',
    method : 'GET',
    path : '/path/to/url',
    port : 80, // optional
    protocol : 'http', // optional, default 'http'
    query, : { 'gaius' : 'baltar' },// optional, query string as json
    body : { 'kara' : 'thrace' } // optional, form encoded body as json
};
```


Notes
-----
TODO: Add support for RSA-SHA1. Add support for plain Node.js http.
