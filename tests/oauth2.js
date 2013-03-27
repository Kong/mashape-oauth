var assert = require('assert'),
    events = require('events'),
    crypto = require('crypto'),
       url = require('url'),
    OAuth2 = require('../index').OAuth2;

var FakeResponse = function (status) { this.statusCode = status; this.headers = {}; };
FakeResponse.prototype = events.EventEmitter.prototype;
FakeResponse.prototype.setEncoding = function () {};

var FakeRequest = function (response) { this.response = response; };
FakeRequest.prototype = events.EventEmitter.prototype;
FakeRequest.prototype.write = function (body) { this.emit('response', this.response); };
FakeRequest.prototype.end = function () { this.response.emit('end'); };

describe('OAuth2', function () {
  describe('Instance with Client Id and Secret', function () {
    var oa = new OAuth2({
      clientId: "clientId",
      clientSecret: "clientSecret"
    }), prior = { request: oa.request, executeRequest: oa.executeRequest };

    describe('Handling Access Token', function () {
      it('should correctly extract token if recieved as form data', function (done) {
        oa.request = function (options, callback) {
          callback(null, "access_token=access&refresh_token=refresh");
        };

        oa.getOAuthAccessToken("", {}, function (error, access, refresh) {
          assert.equal(access, "access");
          assert.equal(refresh, "refresh");
          oa.request = prior.request;
          done();
        });
      });

      // http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-23#section-2.3
      // See the do not use query url section, it's only if you are unable use header methods.
      // Header authentication is considered higher priority in this case.
      it('should not include access tokens in both the querystring and header', function (done) {
        oa.executeRequest = function (options, callback) {
          callback(null, url.parse(options.path, true).query, options.headers);
        };

        oa.request({
          method: 'GET',
          url: 'http://foo/',
          headers: {
            "Authorization": "Bearer BadNews"
          },
          access_token: 'accessx'
        }, function (error, query, headers) {
          assert.ok(!('access_token' in query), "access_token present in query");
          assert.ok('Authorization' in headers, "Authorization not in headers");
          oa.executeRequest = prior.executeRequest;
          done();
        });
      });

      it('should include access token if authorization header is not set', function (done) {
        oa.executeRequest = function (options, callback) {
          callback(null, url.parse(options.path, true).query, options.headers);
        };

        oa.request({
          method: 'GET',
          url: 'http://foo/',
          access_token: 'accessx'
        }, function (error, query, headers) {
          assert.ok('access_token' in query, "access_token is not present in query");
          assert.ok(!('Authorization' in headers), "Authorization should not be in headers");
          oa.executeRequest = prior.executeRequest;
          done();
        });
      });

      it('should correctly extract the token if recieved as JSON literal', function (done) {
        oa.request = function (options, callback) {
          callback(null, '{"access_token":"access","refresh_token":"refresh"}');
        };

        oa.getOAuthAccessToken("", {}, function (error, access, refresh, results) {
          assert.equal(access, "access");
          assert.equal(refresh, "refresh");
          oa.request = prior.request;
          done();
        });
      });

      it('should return the recieved data to the calling method', function (done) {
        oa.request = function (options, callback) {
          callback(null, '{"access_token":"access","refresh_token":"refresh","extra_1":1, "extra_2":"foo"}');
        };

        oa.getOAuthAccessToken("", {}, function (error, access, refresh, results) {
          assert.equal(access, "access");
          assert.equal(refresh, "refresh");
          assert.notEqual(results, undefined);
          assert.equal(results.extra_1, 1);
          assert.equal(results.extra_2, "foo");
          oa.request = prior.request;
          done();
        });
      });
    });

    describe('Grant Type', function () {
      it('should pass value of code argument as parameter when no grant_type is specified', function (done) {
        oa.request = function (options, callback) {
          assert.notEqual(-1, options.body.indexOf("code=mashape"));
          oa.request = prior.request;
          done();
        };

        oa.getOAuthAccessToken("mashape", {});
      });

      it('should pass value of code argument as parameter when an invalid grant_type is specified', function (done) {
        oa.request = function (options, callback) {
          assert.notEqual(-1, options.body.indexOf("code=mashape"));
          oa.request = prior.request;
          done();
        };

        oa.getOAuthAccessToken("mashape", { grant_type: "refresh_toucan" });
      });

      it('should pass value of code argument as the refresh_token parameter when a grant_type is specified, with no code specified', function (done) {
        oa.request = function (options, callback) {
          assert.notEqual(-1, options.body.indexOf("refresh_token=mashape"));
          assert.notEqual(-1, options.body.indexOf("grant_type=refresh_token"));
          assert.equal(-1, options.body.indexOf("code="));
          oa.request = prior.request;
          done();
        };

        oa.getOAuthAccessToken("mashape", { grant_type: "refresh_token" });
      });
    });

    describe('useAuthHeaderForGet()', function () {
      it('should force usage of access_token as bearer when using', function (done) {
        oa.request = function (options, callback) {
          assert.equal(options.headers.Authorization, "Bearer mashape");
          oa.request = prior.request;
          done();
        };

        oa.useAuthHeaderForGet();
        oa.get("", "mashape");
      });

      it('should force usage of access_token as basic when Auth Method is Basic', function (done) {
        oa.request = function (options, callback) {
          assert.equal(options.headers.Authorization, "Basic mashape");
          oa.request = prior.request;
          oa.authorizationMethod = "Bearer";
          done();
        };

        oa.useAuthHeaderForGet();
        oa.authorizationMethod = "Basic";
        oa.get("", "mashape");
      });

      it('should not provide an Authorization header if not used', function (done) {
        oa.request = function (options, callback) {
          assert.equal(options.headers.Authorization, undefined);
          assert.equal(options.access_token, "mashape");
          oa.request = prior.request;
          done();
        };

        oa.useAuthHeaderForGet(false);
        oa.get("", "mashape");
      });
    });
  });

  describe('Custom Headers', function () {
    var oa = new OAuth2({
      clientId: "clientId",
      clientSecret: "clientSecret",
      headers: {
        'X-Mashape-Proxy': '1.0'
      }
    }), prior = { request: oa.request, executeRequest: oa.executeRequest };

    it('should extend existing headers and mix them in with defaults', function (done) {
      oa.executeRequest = function (options, callback) {
        assert.equal(options.headers["X-Mashape-Proxy"], '1.0');
        oa.executeRequest = prior.executeRequest;
        done();
      };

      oa.get("", "");
    });
  });
});