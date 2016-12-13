var oauther = require('../oauther.js');
var when = require('saywhen');

var consumer_key = 'oauthertest';
var consumer_secret = 'abcd1234';

var token_key = 'tsetrehtuao';
var token_secret = '4321dcba';

describe('HMAC-SHA1', function() {

    var config, request, oauth, req;

    beforeEach(function() {
        config = {
            consumer : { key : consumer_key, secret : consumer_secret },
            signature_method : 'HMAC-SHA1',
            nonce_length : 32
        };

        request = {
            hostname : 'example.com',
            path : '/oauther',
            method : 'GET',
            body : {
                parameter : 'Spec!al(Char*cters[])'
            }
        };

        oauth = oauther(config);

        req = jasmine.createSpyObj('req', ['header']);
    });

    it('generates and validates the signature', function() {
        var sig = oauth.sign(request);
        var header = sig.toHeader();

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';
        req.body = {
            parameter : 'Spec!al(Char*cters[])'
        };

        expect(sig.signature_method).toEqual('HMAC-SHA1');
        expect(oauth.validate(req)).toEqual(true);
    });

    it('generates and validates the signature, with req.baseUrl', function() {
        request.path = '/base/oauther';

        var sig = oauth.sign(request);
        var header = sig.toHeader();

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';
        req.baseUrl = '/base';
        req.body = {
            parameter : 'Spec!al(Char*cters[])'
        };

        expect(sig.signature_method).toEqual('HMAC-SHA1');
        expect(oauth.validate(req)).toEqual(true);
    });

    it('generates and validates the signature, with req.baseUrl and no path', function() {
        request.path = '/base';

        var sig = oauth.sign(request);
        var header = sig.toHeader();

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.baseUrl = '/base';
        req.body = {
            parameter : 'Spec!al(Char*cters[])'
        };

        expect(sig.signature_method).toEqual('HMAC-SHA1');
        expect(oauth.validate(req)).toEqual(true);
    });

    it('validates a known signature', function() {
        var header = 'OAuth realm="",oauth_version="1.0",oauth_consumer_key="oauthertest",oauth_timestamp="1417000000",oauth_nonce="12345678",oauth_signature_method="HMAC-SHA1",oauth_signature="Ry03%2BNtdAvaW0wUfFZ3mTfwqyPk%3D"';

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';
        req.query = {test : 'data'};

        expect(oauth.validate(req)).toEqual(true);
    });

    it('validates a known signature with special characters in the body', function() {
        var header = 'OAuth oauth_nonce="3355101671",oauth_signature="lW%2BHyvNIjJD%2BW%2BLW6sUsezazIyI%3D",oauth_consumer_key="oauthertest",oauth_timestamp="1481625077",oauth_signature_method="HMAC-SHA1",oauth_version="1.0"';

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'PUT';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';
        req.body = {
            parameter : 'Spec!al(Char*cters[])'
        };

        expect(oauth.validate(req)).toEqual(true);
    });

    it('validates a known signature from the query string', function() {
        when(req.header).isCalledWith('Authorization').thenReturn(undefined);

        req.query = {
            oauth_version : '1.0',
            oauth_consumer_key : 'oauthertest',
            oauth_timestamp : '1417000000',
            oauth_nonce : '12345678',
            oauth_signature_method : 'HMAC-SHA1',
            oauth_signature : 'Ry03+NtdAvaW0wUfFZ3mTfwqyPk=',
            test : 'data'
        };
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';

        expect(oauth.validate(req)).toEqual(true);
    });

    it('fails if no authorization header or query params', function() {
        when(req.header).isCalledWith('Authorization').thenReturn(undefined);

        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';

        expect(oauth.validate(req)).toEqual(false);
    });

    it('generates and validates the signature with a configured oauth_token', function() {
        config.token = { key : token_key, secret : token_secret };
        oauth = oauther(config);

        var sig = oauth.sign(request);
        var header = sig.toHeader();

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';
        req.body = {
            parameter : 'Spec!al(Char*cters[])'
        };

        expect(sig.signature_method).toEqual('HMAC-SHA1');
        expect(oauth.validate(req)).toEqual(true);
    });

    it('validates a known signature with a configured oauth_token', function() {
        config.token = { key : token_key, secret : token_secret };
        oauth = oauther(config);

        var header = 'OAuth realm="",oauth_version="1.0",oauth_consumer_key="oauthertest",oauth_token="tsetrehtuao",oauth_timestamp="1417000000",oauth_nonce="12345678",oauth_signature_method="HMAC-SHA1",oauth_signature="2oA72F2tOQBGyITCgaDr4p3bayQ="';

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';

        expect(oauth.validate(req)).toEqual(true);
    });
});

describe('PLAINTEXT', function() {
    var config, request, oauth, req;

    beforeEach(function() {
        config = {
            consumer : { key : consumer_key, secret : consumer_secret },
            signature_method : 'PLAINTEXT',
            nonce_length : 32
        };

        request = {
            hostname : 'example.com',
            path : '/oauther',
            method : 'GET',
            body : {
                parameter : 'Spec!al(Char*cters[])'
            }
        };

        oauth = oauther(config);

        req = jasmine.createSpyObj('req', ['header']);
    });

    it('generates and validates the signature', function() {
        var sig = oauth.sign(request);
        var header = sig.toHeader();

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';
        req.body = {
            parameter : 'Spec!al(Char*cters[])'
        };

        expect(sig.signature_method).toEqual('PLAINTEXT');
        expect(oauth.validate(req)).toEqual(true);
    });

    it('validates a known signature', function() {
        var header = 'OAuth realm="",oauth_version="1.0",oauth_consumer_key="oauthertest",oauth_timestamp="1417000000",oauth_nonce="12345678",oauth_signature_method="PLAINTEXT",oauth_signature="abcd1234%26"';

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';

        expect(oauth.validate(req)).toEqual(true);
    });

    it('validates a known signature from the query string', function() {
        when(req.header).isCalledWith('Authorization').thenReturn(undefined);

        req.query = {
            oauth_version : '1.0',
            oauth_consumer_key : 'oauthertest',
            oauth_timestamp : '1417000000',
            oauth_nonce : '12345678',
            oauth_signature_method : 'PLAINTEXT',
            oauth_signature : 'abcd1234&'
        };
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';

        expect(oauth.validate(req)).toEqual(true);
    });

    it('fails if no authorization header or query params', function() {
        when(req.header).isCalledWith('Authorization').thenReturn(undefined);

        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';

        expect(oauth.validate(req)).toEqual(false);
    });

    it('generates and validates the signature with a configured oauth_token', function() {
        config.token = { key : token_key, secret : token_secret };
        oauth = oauther(config);

        var sig = oauth.sign(request);
        var header = sig.toHeader();

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';
        req.body = {
            parameter : 'Spec!al(Char*cters[])'
        };

        expect(sig.signature_method).toEqual('PLAINTEXT');
        expect(oauth.validate(req)).toEqual(true);
    });

    it('validates a known signature with a configured oauth_token', function() {
        config.token = { key : token_key, secret : token_secret };
        oauth = oauther(config);

        var header = 'OAuth realm="",oauth_version="1.0",oauth_consumer_key="oauthertest",oauth_token="tsetrehtuao",oauth_timestamp="1417000000",oauth_nonce="12345678",oauth_signature_method="PLAINTEXT",oauth_signature="abcd1234&4321dcba"';

        when(req.header).isCalledWith('Authorization').thenReturn(header);
        req.method = 'GET';
        req.hostname = 'example.com';
        req.protocol = 'http';
        req.path = '/oauther';

        expect(oauth.validate(req)).toEqual(true);
    });
});
