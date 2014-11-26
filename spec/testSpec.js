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
        describe('signature tests body only', function() {
            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data',
                    oauth_consumer_key : consumer_key,
                    oauth_nonce : '12345678',
                    oauth_signature_method : 'HMAC-SHA1',
                    oauth_timestamp : '1417000000',
                    oauth_version : '1.0'
                };
                req.query = {};

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(consumer_secret);
                var signed = oauth.sign(req);

                expect(oauth.validate(signed)).toEqual(true);
            });

            it('generates the expected signature', function() {
                // expected generated at http://oauth.googlecode.com/svn/code/javascript/example/signature.html
                var expected = 'Ry03+NtdAvaW0wUfFZ3mTfwqyPk=';

                var oauth = oauther(consumer_secret);
                var signed = oauth.sign(req);

                expect(req.body.oauth_signature).toEqual(expected);
            });
        });

        describe('signature tests query only', function() {

            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data'
                };
                req.query = {
                    oauth_consumer_key : consumer_key,
                    oauth_nonce : '12345678',
                    oauth_signature_method : 'HMAC-SHA1',
                    oauth_timestamp : '1417000000',
                    oauth_version : '1.0'
                };

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(consumer_secret);
                var signed = oauth.sign(req);

                expect(oauth.validate(signed)).toEqual(true);
            });
        });

        describe('signature tests OAuth header', function() {
            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data'
                };
                req.query = {};

                header['Authorization'] = 'OAuth oauth_consumer_key="'+consumer_key+'", oauth_nonce="12345678", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1417000000", oauth_version="1.0"';

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(consumer_secret);
                var signed = oauth.sign(req);

                expect(oauth.validate(signed)).toEqual(true);
            });
        });
    });

    describe('PLAINTEXT tests', function() {
        describe('signature tests body only', function() {

            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data',
                    oauth_consumer_key : consumer_key,
                    oauth_nonce : '12345678',
                    oauth_signature_method : 'PLAINTEXT',
                    oauth_timestamp : '1417000000',
                    oauth_version : '1.0'
                };
                req.query = {};

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(consumer_secret);
                var signed = oauth.sign(req);

                expect(oauth.validate(signed)).toEqual(true);
            });

            it('generates the expected signature', function() {
                // expected generated at http://oauth.googlecode.com/svn/code/javascript/example/signature.html
                var expected = consumer_secret+'&';

                var oauth = oauther(consumer_secret);
                var signed = oauth.sign(req);

                expect(req.body.oauth_signature).toEqual(expected);
            });
        });

        describe('signature tests query only', function() {

            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data'
                };
                req.query = {
                    oauth_consumer_key : consumer_key,
                    oauth_nonce : '12345678',
                    oauth_signature_method : 'PLAINTEXT',
                    oauth_timestamp : '1417000000',
                    oauth_version : '1.0'
                };

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(consumer_secret);
                var signed = oauth.sign(req);

                expect(oauth.validate(signed)).toEqual(true);
            });
        });

        describe('signature tests OAuth header', function() {

            beforeEach(function() {

                req.method = "GET";
                req.body = {
                    test : 'data'
                };
                req.query = {};

                header['Authorization'] = 'OAuth oauth_consumer_key="'+consumer_key+'", oauth_nonce="12345678", oauth_signature_method="PLAINTEXT", oauth_timestamp="1417000000", oauth_version="1.0"';

                req.hostname = 'example.com';
                req.protocol = 'http';
                req.path = '/oauther';
            });

            it('generates and validates the signature', function() {
                var oauth = oauther(consumer_secret);
                var signed = oauth.sign(req);

                expect(oauth.validate(signed)).toEqual(true);
            });
        });
    });
});
