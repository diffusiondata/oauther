var crypto = require('crypto');
var url = require('url');
var qs = require('querystring');

var config;

function oauther(config) {
    var self = this;
    this.consumer = config.consumer;
    this.token = config.token;
    this.signature_method = config.signature_method || 'HMAC-SHA1';
    this.nonce_length = config.nonce_length || 32;
    this.version = "1.0";

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

    function getNonce(length) {
        var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        var nonce = '';

        for(var i = 0; i < this.nonce_length; i++) {
            nonce += chars[parseInt(Math.random() * chars.length, 10)];
        }

        return nonce;
    }

    function generateSignature(method, baseURL, params) {
        params.oauth_signature_method = this.signature_method;
        params.oauth_consumer_key = this.consumer.key;
        params.oauth_nonce = getNonce();
        params.oauth_timestamp = (new Date().getTime()) / 1000.0;
        params.oauth_version = this.version;
        var signature = calculateSignature(method, baseURL, params);
        params.oauth_signature = signature;
        return params;
    };

    function calculateSignature(method, baseURL, params) {
        var baseString = method.toUpperCase() + '&' + qs.escape(baseURL) + '&' + qs.escape(parseParameters(params));

        var csecret = config.consumer ? config.consumer.secret : '';
        var tsecret = config.token ? config.token.secret : '';

        var keyString = qs.escape(csecret) + '&' + qs.escape(tsecret);

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

    function updateHeader(req, params) {
        req.header('Authorization', getOAuthHeader(params));
        return req;
    };

    this.sign = function(req) {
        var method = req.method;
        var baseURL = parseURL(req);
        var params = getAllParams(req);
        var oauthParams = generateSignature(method, baseURL, params);
        return updateHeader(req, oauthParams);
    };

    this.validate = function(req) {
        var method = req.method;
        var baseURL = parseURL(req);
        var params = getAllParams(req);

        var oauthparams = getAllParams(req);

        var expect = calculateSignature(method, baseURL, params);

        return oauthparams['oauth_signature'] === expect;
    };

    return self;
};

module.exports = oauther;
