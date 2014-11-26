var oauther = require('../oauther.js');
var when = require('saywhen');

describe('oauther tests', function() {
    var req = jasmine.createSpyObj('req', ['header'])

    var consumer_key = 'oauthertest';
    var consumer_secret = 'abcd1234';

    describe('HMAC-SHA1 tests', function() {
        var config = {
            consumer : { key : consumer_key, secret : consumer_secret },
            signature_method : 'HMAC-SHA1',
            nonce_length : 32
        };

        var request = {
            hostname : 'example.com',
            path : '/oauther',
            method : 'GET'
        };

        it('generates and validates the signature', function() {
            var oauth = oauther(config);
            var sig = oauth.sign(request);

            var header = sig.toHeader();

            when(req.header).isCalledWith('Authorization').thenReturn(header);
            req.method = 'GET';
            req.hostname = 'example.com';
            req.protocol = 'http';
            req.path = '/oauther';

            expect(oauth.validate(req)).toEqual(true);
        });

        it('validates a known signature', function() {
            var oauth = oauther(config);
            var sig = oauth.sign(request);

            var header = 'OAuth realm="",oauth_version="1.0",oauth_consumer_key="oauthertest",oauth_timestamp="1417000000",oauth_nonce="12345678",oauth_signature_method="HMAC-SHA1",oauth_signature="Ry03%2BNtdAvaW0wUfFZ3mTfwqyPk%3D"';

            when(req.header).isCalledWith('Authorization').thenReturn(header);
            req.method = 'GET';
            req.hostname = 'example.com';
            req.protocol = 'http';
            req.path = '/oauther';

            expect(oauth.validate(req)).toEqual(true);
        });
    });

    describe('PLAINTEXT tests', function() {
        var config = {
            consumer : { key : consumer_key, secret : consumer_secret },
            signature_method : 'PLAINTEXT',
            nonce_length : 32
        };

        var request = {
            hostname : 'example.com',
            path : '/oauther',
            method : 'GET'
        };

        it('generates and validates the signature', function() {
            var oauth = oauther(config);
            var sig = oauth.sign(request);

            var header = sig.toHeader();

            when(req.header).isCalledWith('Authorization').thenReturn(header);
            req.method = 'GET';
            req.hostname = 'example.com';
            req.protocol = 'http';
            req.path = '/oauther';

            expect(oauth.validate(req)).toEqual(true);
        });

        it('validates a known signature', function() {
            var oauth = oauther(config);
            var sig = oauth.sign(request);

            var header = 'OAuth realm="",oauth_version="1.0",oauth_consumer_key="oauthertest",oauth_timestamp="1417000000",oauth_nonce="12345678",oauth_signature_method="PLAINTEXT",oauth_signature="abcd1234%26"';

            when(req.header).isCalledWith('Authorization').thenReturn(header);
            req.method = 'GET';
            req.hostname = 'example.com';
            req.protocol = 'http';
            req.path = '/oauther';

            expect(oauth.validate(req)).toEqual(true);
        });
    });
});
