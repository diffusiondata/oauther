var oauther = require('../oauther.js');
var when = require('saywhen');

describe('oauther tests', function() {
    var req = jasmine.createSpyObj('req', ['header', 'method', 'body', 'query', 'hostname', 'protocol', 'path'])

    var consumer_key = 'oauthertest';
    var consumer_secret = 'abcd1234';
    var header = {};

    beforeEach(function() {
        header = {};
        when(req.header).isCalledWith(jasmine.any(String), jasmine.any(String)).then(function(key, value) {
            header[key] = value;
        });
        when(req.header).isCalledWith(jasmine.any(String)).then(function(key) {
            return header[key];
        });
    });

    describe('HMAC-SHA1 tests', function() {
        var config = {
            consumer : { key : consumer_key, secret : consumer_secret },
            signature_method : 'HMAC-SHA1',
            nonce_length : 32
        };
        describe('signature test', function() {
            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data'
                };
                req.query = {};

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(config);
                var signed = oauth.sign(req);

                expect(oauth.validate(signed)).toEqual(true);
            });
        });

        describe('signature test OAuth header', function() {
            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data'
                };
                req.query = {};

                header['Authorization'] = 'OAuth oauth_consumer_key="'+consumer_key+'", oauth_nonce="12345678", oauth_signature="Ry03%2BNtdAvaW0wUfFZ3mTfwqyPk%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1417000000", oauth_version="1.0"';

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('validates the signature', function() {
                var oauth = oauther(config);

                expect(oauth.validate(req)).toEqual(true);
            });
        });
    });

    describe('PLAINTEXT tests', function() {
        var config = {
            consumer : { key : consumer_key, secret : consumer_secret },
            signature_method : 'PLAINTEXT',
            nonce_length : 32
        };
        describe('signature test', function() {

            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data'
                };
                req.query = {};

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(config);
                var signed = oauth.sign(req);

                expect(oauth.validate(signed)).toEqual(true);
            });
        });

        describe('signature test OAuth header', function() {

            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data'
                };
                req.query = {};

                header['Authorization'] = 'OAuth oauth_consumer_key="'+consumer_key+'", oauth_nonce="12345678", oauth_signature="'+consumer_secret+'&", oauth_signature_method="PLAINTEXT", oauth_timestamp="1417000000", oauth_version="1.0"';

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(config);

                expect(oauth.validate(req)).toEqual(true);
            });
        });
    });
});
