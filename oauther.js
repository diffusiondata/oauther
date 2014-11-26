var crypto = require('crypto');
var url = require('url');
var qs = require('querystring');

var cSecret, tSecret;

function parseParameters(params) {
    var paramString = '';

    Object.keys(params).sort().forEach(function(key) {
        if (key !== 'oauth_signature') {
            var val = params[key];
            paramString += (paramString ? '&' : '');
            paramString += key + '=' + qs.escape(val);
        }
    });

    return paramString;
};

function getAllParams(req) {
    var params = {};

    for (var key in req.body) {
        params[key] = req.body[key];
    }
    for (var key in req.query) {
        params[key] = req.query[key];
    }

    var oauthparams = getOAuthHeaderParams(req);
    for (var key in oauthparams) {
        params[key] = oauthparams[key];
    }

    return params;
};

function getOAuthHeaderParams(req) {
    var oauthParams = {};

    var authHeader = req.header('Authorization');
    if(authHeader && authHeader.match(/^OAuth/)) {
        var params = authHeader.match(/[^=\s]+="[^"]*"(?:)?/g);
        params.forEach(function(p) {
            var kv = p.split('=');
            oauthParams[qs.unescape(kv[0])] = qs.unescape(kv[1].match(/[^"]{1,}[^"]/)[0]);
        });
    }
    return oauthParams;
};

function getOAuthHeader(params) {
    var header = '';

    for (var key in params) {
        header += (header ? ', ' : '') + key + '="' + qs.escape(params[key])+'"';
    }
    return 'OAuth '+header;
};

function parseURL(req) {
    var host = req.hostname;
    var port = req.port;
    var protocol = req.protocol;
    var path = req.path;

    var baseURL = protocol + '://' + host;

    if (port && (protocol !== 'http' || protocol !== 'https')) {
        baseURL += ':' + port;
    }

    baseURL += path;

    return baseURL;
};

function generateSignature(method, baseURL, params) {
    var baseString = method.toUpperCase() + '&' + qs.escape(baseURL) + '&' + qs.escape(parseParameters(params));

    var keyString = qs.escape(cSecret) + '&' + qs.escape(tSecret);

    if (params['oauth_signature_method'] === 'PLAINTEXT') {
        return keyString;
    }
    else if (params['oauth_signature_method'] === 'HMAC-SHA1') {
        var hmac = crypto.createHmac('sha1', keyString);
        hmac.update(baseString);

        return hmac.digest('base64');
    }
    else {
        throw 'oauther :: Unsupported signature method : ' + params['oauth_signature_method'];
    }
};

function signRequest(req, signature) {
    if (req.body.oauth_signature_method) {
        req.body.oauth_signature = signature;
    }
    else if (req.query.oauth_signature_method) {
        req.query.oauth_signature = signature;
    }
    else if (req.header('Authorization').match(/^OAuth/)) {
        params = getOAuthHeaderParams(req);
        params.oauth_signature = signature;
        req.header('Authorization', getOAuthHeader(params));
    }
    return req;
};

function oauther(consumerSecret, tokenSecret) {
    var self = this;
    cSecret = consumerSecret ? consumerSecret : '';
    tSecret = tokenSecret ? tokenSecret : '';

    this.sign = function(req) {
        var method = req.method;
        var baseURL = parseURL(req);
        var params = getAllParams(req);

        var signature = generateSignature(method, baseURL, params);
        return signRequest(req, signature);
    };

    this.validate = function(req) {
        var method = req.method;
        var baseURL = parseURL(req);
        var params = getAllParams(req);

        var oauthparams = getAllParams(req);

        var expect = generateSignature(method, baseURL, params);

        return oauthparams['oauth_signature'] === expect;
    };

    return self;
};

module.exports = oauther;
