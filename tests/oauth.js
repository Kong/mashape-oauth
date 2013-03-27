var assert = require('assert'),
    events = require('events'),
    crypto = require('crypto'),
    OAuth = require('../lib/oauth');

var FakeResponse = function (status) { this.statusCode = status; this.headers = {}; };
FakeResponse.prototype = events.EventEmitter.prototype;
FakeResponse.prototype.setEncoding = function () {};

var FakeRequest = function (response) { this.response = response; };
FakeRequest.prototype = events.EventEmitter.prototype;
FakeRequest.prototype.write = function (body) { this.emit('response', this.response); };
FakeRequest.prototype.end = function () { this.response.emit('end'); };

//Valid RSA keypair used to test RSA-SHA1 signature method
var RSAPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
"MIICXQIBAAKBgQDizE4gQP5nPQhzof/Vp2U2DDY3UY/Gxha2CwKW0URe7McxtnmE\n" +
"CrZnT1n/YtfrrCNxY5KMP4o8hMrxsYEe05+1ZGFT68ztms3puUxilU5E3BQMhz1t\n" +
"JMJEGcTt8nZUlM4utli7fHgDtWbhvqvYjRMGn3AjyLOfY8XZvnFkGjipvQIDAQAB\n" +
"AoGAKgk6FcpWHOZ4EY6eL4iGPt1Gkzw/zNTcUsN5qGCDLqDuTq2Gmk2t/zn68VXt\n" +
"tVXDf/m3qN0CDzOBtghzaTZKLGhnSewQ98obMWgPcvAsb4adEEeW1/xigbMiaW2X\n" +
"cu6GhZxY16edbuQ40LRrPoVK94nXQpj8p7w4IQ301Sm8PSECQQD1ZlOj4ugvfhEt\n" +
"exi4WyAaM45fylmN290UXYqZ8SYPI/VliDytIlMfyq5Rv+l+dud1XDPrWOQ0ImgV\n" +
"HJn7uvoZAkEA7JhHNmHF9dbdF9Koj86K2Cl6c8KUu7U7d2BAuB6pPkt8+D8+y4St\n" +
"PaCmN4oP4X+sf5rqBYoXywHlqEei2BdpRQJBAMYgR4cZu7wcXGIL8HlnmROObHSK\n" +
"OqN9z5CRtUV0nPW8YnQG+nYOMG6KhRMbjri750OpnYF100kEPmRNI0VKQIECQE8R\n" +
"fQsRleTYz768ahTVQ9WF1ySErMwmfx8gDcD6jjkBZVxZVpURXAwyehopi7Eix/VF\n" +
"QlxjkBwKIEQi3Ks297kCQQCL9by1bueKDMJO2YX1Brm767pkDKkWtGfPS+d3xMtC\n" +
"KJHHCqrS1V+D5Q89x5wIRHKxE5UMTc0JNa554OxwFORX\n" +
"-----END RSA PRIVATE KEY-----";

var RSAPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDizE4gQP5nPQhzof/Vp2U2DDY3\n" +
"UY/Gxha2CwKW0URe7McxtnmECrZnT1n/YtfrrCNxY5KMP4o8hMrxsYEe05+1ZGFT\n" +
"68ztms3puUxilU5E3BQMhz1tJMJEGcTt8nZUlM4utli7fHgDtWbhvqvYjRMGn3Aj\n" +
"yLOfY8XZvnFkGjipvQIDAQAB\n" +
"-----END PUBLIC KEY-----";

describe('OAuth 1.0a', function () {
  describe('Generating HMAC-SHA1 Signature', function () {
    it('should generate the expected result string', function (done) {
      var result = new OAuth({
        signatureMethod: OAuth.signatures.hmac
      }).createSignatureBase(
        'GET',
        'http://photos.example.net/photos',
        'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original'
      );

      assert.equal(result, "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal");
      done();
    });
  });

  describe('Generating PLAINTEXT Signature', function () {
    it('should generate the expected result string', function (done) {
      var result = new OAuth({
        signatureMethod: OAuth.signatures.plaintext
      }).getSignature({
        method: 'GET',
        url: 'http://photos.example.net/photos',
        parameters: 'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original',
        token_secret: 'test'
      });

      assert.equal(result, "&test");
      done();
    });
  });

  describe('Generating RSA-SHA1 Signature', function () {
    it('should generate a valid OAuth Signature', function (done) {
      var oa = new OAuth({
        consumerSecret: RSAPrivateKey,
        signatureMethod: OAuth.signatures.rsa
      }), base = oa.createSignatureBase(
        'GET',
        'http://photos.example.net/photos',
        'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=RSA-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original'
      ), signature = oa.createSignature(base, "xyz4992k83j47x0b");
      assert.equal(signature, "qS4rhWog7GPgo4ZCJvUdC/1ZAax/Q4Ab9yOBvgxSopvmKUKp5rso+Zda46GbyN2hnYDTiA/g3P/d/YiPWa454BEBb/KWFV83HpLDIoqUUhJnlXX9MqRQQac0oeope4fWbGlfTdL2PXjSFJmvfrzybERD/ZufsFtVrQKS3QBpYiw=");

      var verifier = crypto.createVerify(OAuth.signatures.rsa).update(base);
      var valid = verifier.verify(RSAPublicKey, signature, 'base64');
      assert.ok(valid, "Signature could not be verified with RSA public key");

      done();
    });
  });

  describe('Normalising URL', function () {
    it('should strip default ports', function (done) {
      assert.equal(OAuth.normalizeUrl('https://host.com:443/foo/bar'), 'https://host.com/foo/bar');
      done();
    });

    it('should leave in non-default ports for use in signature generation', function (done) {
      assert.equal(OAuth.normalizeUrl('https://host.com:446/foo/bar'), 'https://host.com:446/foo/bar');
      assert.equal(OAuth.normalizeUrl('http://host.com:81/foo/bar'), 'http://host.com:81/foo/bar');
      done();
    });

    it('should add trailing slash when no path is present', function (done) {
      assert.equal(OAuth.normalizeUrl('http://host.com'), 'http://host.com/');
      done();
    });
  });

  describe('Creating Argument Tuples', function () {
    var parameters = {
      "z": "a",
      "a": ["1", "2"],
      "1": "c"
    };

    it('should flatten argument arrays', function (done) {
      var results = OAuth.tupleArguments(parameters);

      assert.equal(results.length, 4);
      assert.equal(results[0][0], "1");
      assert.equal(results[1][0], "z");
      assert.equal(results[2][0], "a");
      assert.equal(results[3][0], "a");
      done();
    });

    it('should order tuples by argument name', function (done) {
      var results = OAuth.tupleSorter(OAuth.tupleArguments(parameters));

      assert.equal(results[0][0], "1");
      assert.equal(results[1][0], "a");
      assert.equal(results[2][0], "a");
      assert.equal(results[3][0], "z");
      done();
    });

    it('should order two parameter names of equal value by value', function (done) {
      parameters = { "z": "a", "a": ["z", "b", "b", "a", "y"], "1": "c" };
      var results = OAuth.tupleSorter(OAuth.tupleArguments(parameters));

      assert.equal(results[0][0], "1");
      assert.equal(results[1][0], "a");
      assert.equal(results[1][1], "a");
      assert.equal(results[2][0], "a");
      assert.equal(results[2][1], "b");
      assert.equal(results[3][0], "a");
      assert.equal(results[3][1], "b");
      assert.equal(results[4][0], "a");
      assert.equal(results[4][1], "y");
      assert.equal(results[5][0], "a");
      assert.equal(results[5][1], "z");
      assert.equal(results[6][0], "z");
      done();
    });

    describe('Normalising Arguments', function () {
      it('should encode and order as per Section 3.1', function (done) {
        parameters = {
          "b5": "=%3D",
          "a3": ["a", "2 q"],
          "c@": "",
          "a2": "r b",
          "oauth_consumer_key": "9djdj82h48djs9d2",
          "oauth_token":"kkk9d7dh3k39sjv7",
          "oauth_signature_method": "HMAC-SHA1",
          "oauth_timestamp": "137131201",
          "oauth_nonce": "7d8f3e4a",
          "c2" :  ""
        };

        var results = OAuth.normalizeArguments(parameters);
        assert.equal(results, "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7");
        done();
      });
    });
  });

  describe('Signing', function () {
    var oa = new OAuth({
      consumerKey: "consumerkey",
      consumerSecret: "consumersecret",
      signatureMethod: OAuth.signatures.hmac,
      version: "1.0",

      // Custom Timestamp Method
      timestamp: function () {
        return "1272399856";
      },

      // Custom Nonce Method
      nonce: function () {
        return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp";
      }
    });

    describe('Preparing Parameters', function () {
      it('should understand Object Notation style url parameters', function (done) {
        var results = oa.prepareParameters({
          url: "http://host.com/?foo[bar]=x&bar[foo]=y&m=a&m=b",
          method: "GET"
        });

        assert.equal(results[0][0], "bar[foo]");
        assert.equal(results[0][1], "y");
        assert.equal(results[1][0], "foo[bar]");
        assert.equal(results[1][1], "x");
        assert.equal(results[2][0], "m");
        assert.equal(results[2][1], "a");
        assert.equal(results[3][0], "m");
        assert.equal(results[3][1], "b");

        done();
      });

      it('should make sure multi-value parameters are not turned into Object Notation', function (done) {
        var results = oa.prepareParameters({
          url: "http://host.com/?foo=b&foo=a",
          method: "GET"
        });

        assert.equal(results[0][0], "foo");
        assert.equal(results[0][1], "a");
        assert.equal(results[1][0], "foo");
        assert.equal(results[1][1], "b");

        done();
      });

      describe('Two-Legged', function () {
        it('should allow oauth_token to be blank', function (done) {
          var results = oa.prepareParameters({
            url: "http://host.com/?foo=b&foo=a",
            method: "GET",
            oauth_token: ""
          });

          assert.equal(results[6][1], "");
          done();
        });
      });
    });

    describe('URL', function () {
      it('should provide valid signature with no token present', function (done) {
        assert.equal(
          oa.signUrl("http://host.com:3323/foo/bar?bar=foo"), "http://host.com:3323/foo/bar?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_version=1.0&oauth_signature=SGZxq9z05h0XNn5uxocM%2FBBM9wc%3D");
        done();
      });

      it('should provide valid signature with token present', function (done) {
        assert.equal(
          oa.signUrl('http://host.com:3323/foo/bar?bar=foo', 'token'),
          'http://host.com:3323/foo/bar?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=4Qq0OJpHH4rDmsU2jNeWbJzt19k%3D'
        );
        done();
      });

      it('should provide valid signature with both token and secret present', function (done) {
        assert.equal(
          oa.signUrl('http://host.com:3323/foo/bar?bar=foo', 'token', "secret"),
          'http://host.com:3323/foo/bar?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=fP05nZ%2FVRum1Vdp9inEzs1F6GRw%3D'
        );
        done();
      });
    });
  });

  describe('Tokens', function () {
    describe('Request', function () {
      var oa = new OAuth({
        consumerKey: "consumerkey",
        consumerSecret: "consumersecret",
        signatureMethod: OAuth.signatures.hmac,
        version: "1.0",

        // Custom Timestamp Method
        timestamp: function () {
          return "1272399856";
        },

        // Custom Nonce Method
        nonce: function () {
          return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp";
        }
      });

      oa.performSecureRequest = function () {
        this.requestArguments = arguments;
      };

      it('should use POST by default', function (done) {
        oa.setClientOptions();
        oa.getOAuthRequestToken(function(){});
        assert.equal(oa.requestArguments[0].method, 'POST');
        done();
      });

      it('should use HTTP method over-rided through client options', function (done) {
        oa.setClientOptions({ requestTokenHttpMethod: 'GET' });
        oa.getOAuthRequestToken(function(){});
        assert.equal(oa.requestArguments[0].method, 'GET');
        done();
      });
    });

    describe('Access', function () {
      var oa = new OAuth({
        consumerKey: "consumerkey",
        consumerSecret: "consumersecret",
        signatureMethod: OAuth.signatures.hmac,
        version: "1.0",

        // Custom Timestamp Method
        timestamp: function () {
          return "1272399856";
        },

        // Custom Nonce Method
        nonce: function () {
          return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp";
        }
      });

      oa.performSecureRequest = function () {
        this.requestArguments = arguments;
      };

      it('should use POST by default', function (done) {
        oa.setClientOptions();
        oa.getOAuthAccessToken(function(){});
        assert.equal(oa.requestArguments[0].method, 'POST');
        done();
      });

      it('should use HTTP method over-rided through client options', function (done) {
        oa.setClientOptions({ accessTokenHttpMethod: 'GET' });
        oa.getOAuthAccessToken(function(){});
        assert.equal(oa.requestArguments[0].method, 'GET');
        done();
      });
    });
  });

  describe('Authorization Headers', function () {
    var oa = new OAuth({
      consumerKey: "consumerkey",
      consumerSecret: "consumersecret",
      signatureMethod: OAuth.signatures.hmac,
      version: "1.0",

      // Custom Timestamp Method
      timestamp: function () {
        return "1272399856";
      },

      // Custom Nonce Method
      nonce: function () {
        return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp";
      }
    });

    oa.performSecureRequest = function () {
      this.requestArguments = arguments;
    };

    it('should provide a valid signature when token and secret are present', function (done) {
      assert.equal( oa.authHeader("http://host.com:3323/foo/bar?bar=foo", "token", "tokensecret"), 'OAuth oauth_consumer_key="consumerkey",oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1272399856",oauth_token="token",oauth_version="1.0",oauth_signature="7Bgx0d8AfIkL%2FGEV5K2olKVdH6o%3D"');
      done();
    });

    it ('should support variable whitepace separating the arguments', function (done) {
      oa.parameterSeperator = ", ";
      assert.equal(oa.authHeader('http://host.com:3323/foo/bar?bar=foo', 'token', 'tokensecret'), 'OAuth oauth_consumer_key="consumerkey", oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1272399856", oauth_token="token", oauth_version="1.0", oauth_signature="7Bgx0d8AfIkL%2FGEV5K2olKVdH6o%3D"');
      done();
    });
  });

  describe('Non-Standard Ports', function () {
    it('should correctly define host headers', function (done) {
      var oa = new OAuth({
        signatureMethod: OAuth.signatures.hmac
      }), mockProvider = {};

      oa.createClient = function (options) {
        assert.equal(options.headers.Host, "host.com:8080");
        assert.equal(options.host, "host.com");
        assert.equal(options.port, "8080");

        return {
          on: function () {},
          end: function () {}
        };
      };

      oa.get("http://host.com:8080", "GET", "oauth_token", null, function () {});
      done();
    });
  });

  describe('Building OAuth Authorization Header', function () {
    var oa = new OAuth({
      signatureMethod: OAuth.signatures.hmac
    });

    it('should concatenate oauth arguments correctly', function (done) {
      var parameters = [
        ["oauth_timestamp",         "1234567"],
        ["oauth_nonce",             "ABCDEF"],
        ["oauth_version",           "1.0"],
        ["oauth_signature_method",  "HMAC-SHA1"],
        ["oauth_consumer_key",      "asdasdnm2321b3"]
      ];

      assert.equal(oa.buildAuthorizationHeaders(parameters),
        'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"'
      );

      done();
    });

    it('should only concatenate oauth arguments, others should be ignored', function (done) {
      var parameters = [
        ["foo",                     "2343"],
        ["oauth_timestamp",         "1234567"],
        ["oauth_nonce",             "ABCDEF"],
        ["bar",                     "dfsdfd"],
        ["oauth_version",           "1.0"],
        ["oauth_signature_method",  "HMAC-SHA1"],
        ["oauth_consumer_key",      "asdasdnm2321b3"],
        ["foobar",                  "asdasdnm2321b3"]
      ];

      assert.equal(oa.buildAuthorizationHeaders(parameters),
        'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"'
      );

      done();
    });

    it('should always show realm if it exists regardless of being OAuth Echo settings', function (done) {
      var parameters = [
        ["realm",                   "host.com"],
        ["oauth_timestamp",         "1234567"],
        ["oauth_nonce",             "ABCDEF"],
        ["bar",                     "dfsdfd"],
        ["oauth_version",           "1.0"],
        ["oauth_signature_method",  "HMAC-SHA1"],
        ["oauth_consumer_key",      "asdasdnm2321b3"],
        ["foobar",                  "asdasdnm2321b3"]
      ];

      assert.equal(oa.buildAuthorizationHeaders(parameters),
        'OAuth realm="host.com",oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"'
      );

      done();
    });

    it('should not depend on Array.prototype.toString', function (done) {
      var _toString = Array.prototype.toString, parameters;
      Array.prototype.toString = function(){ return '[Array] ' + this.length; };

      parameters= [
        ["foo",                     "2343"],
        ["oauth_timestamp",         "1234567"],
        ["oauth_nonce",             "ABCDEF"],
        ["bar",                     "dfsdfd"],
        ["oauth_version",           "1.0"],
        ["oauth_signature_method",  "HMAC-SHA1"],
        ["oauth_consumer_key",      "asdasdnm2321b3"],
        ["foobar",                  "asdasdnm2321b3"]
      ];

      assert.equal(oa.buildAuthorizationHeaders(parameters),
        'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"'
      );

      Array.prototype.toString = _toString;
      done();
    });
  });

  describe('Performing Secure Request', function () {
    describe('Methods', function () {
      it('should make any extra parameters passed part of the body', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          callback: 'http://foo.com/callback',
          signatureMethod: OAuth.signatures.hmac
        }), written = false;

        oa.createClient = function (options) {
          return {
            write: function (body) {
              written = true;
              assert.equal(body, "scope=foobar%2C1%2C2");
            }
          };
        };

        oa.performSecureRequest({
          oauth_token: 'token',
          oauth_token_secret: 'secret',
          method: 'POST',
          url: 'http://foo.com/protected_resource',
          parameters: {
            scope: "foobar,1,2"
          }
        });

        assert.equal(written, true);

        done();
      });

      it('should return a request object if no callback is passed', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          signatureMethod: OAuth.signatures.hmac
        });

        var request = oa.post('http://foo.com/blah', 'token', 'token_secret', 'BLAH', 'text/plain');
        assert.equal('[object Object]', Object.prototype.toString.call(request));
        assert.equal(request.method, "POST");
        request.end();
        done();
      });

      it('should call internal requests end method and return nothing when callback is passed', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          signatureMethod: OAuth.signatures.hmac
        }), called = false;

        oa.createClient = function (options) {
          return {
            write: function () {},
            on: function () {},
            end: function () { called = true; }
          };
        };

        var request = oa.post('http://foo.com/blah', 'token', 'token_secret', 'BLAH', 'text/plain', function (e, d) {});
        assert.equal(called, true);
        assert.equal(request, undefined);
        done();
      });

      it('should call internal requests end method and return nothing when callback is passed', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          signatureMethod: OAuth.signatures.hmac
        }), called = false;

        oa.createClient = function (options) {
          return {
            write: function () {},
            on: function () {},
            end: function () { called = true; }
          };
        };

        var request = oa.post('http://foo.com/blah', 'token', 'token_secret', 'BLAH', 'text/plain', function (e, d) {});
        assert.equal(called, true);
        assert.equal(request, undefined);
        done();
      });

      it('should be url encoded and content-type set to x-www-form-urlencoded', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          signatureMethod: OAuth.signatures.hmac
        }), called = false;

        oa.createClient = function (options) {
          assert.equal(options.headers['Content-Type'], "application/x-www-form-urlencoded");
          return {
            write: function (data) {
              called = true;
              assert.equal(data, "foo=1%2C2%2C3&bar=1%2B2");
            },
            on: function () {},
            end: function () {}
          };
        };

        var request = oa.post('http://foo.com/blah', 'token', 'token_secret', null, null, { "foo":"1,2,3", "bar":"1+2" });
        assert.equal(called, true);
        done();
      });

      describe('Body is String Type', function () {
        it('should set content-length as byte count not string-count when it contains non-ascii characters', function (done) {
          var oa = new OAuth({
            requestUrl: 'http://term.ie/oauth/example/request_token.php',
            accessUrl: 'http://term.ie/oauth/example/access_token.php',
            consumerKey: 'key',
            consumerSecret: 'secret',
            version: '1.0A',
            signatureMethod: OAuth.signatures.hmac
          }), string = "Tôi yêu node", stringLength = string.length, stringByteLength = Buffer.byteLength(string), called = false;

          // Make sure they differ
          assert.notEqual(stringLength, stringByteLength);

          oa.createClient = function (options) {
            assert.equal(options.headers['Content-Length'], stringByteLength);
            return {
              write: function (data) {
                called = true;
                assert.equal(data, string);
              },
              on: function () {},
              end: function () {}
            };
          };

          var request = oa.post('http://foo.com/blah', 'token', 'token_secret', string);
          assert.equal(called, true);
          done();
        });

        it('should write content-type as default with non-specified, with content-length specified', function (done) {
          var oa = new OAuth({
            requestUrl: 'http://term.ie/oauth/example/request_token.php',
            accessUrl: 'http://term.ie/oauth/example/access_token.php',
            consumerKey: 'key',
            consumerSecret: 'secret',
            version: '1.0A',
            signatureMethod: OAuth.signatures.hmac
          }), string = "foo=1%2C2%2C3&bar=1%2B2", stringLength = string.length, stringByteLength = Buffer.byteLength(string), called = false;

          oa.createClient = function (options) {
            assert.equal(options.headers['Content-Type'], 'application/x-www-form-urlencoded');
            assert.equal(options.headers['Content-Length'], stringByteLength);
            return {
              write: function (data) {
                called = true;
                assert.equal(data, string);
              },
              on: function () {},
              end: function () {}
            };
          };

          var request = oa.post('http://foo.com/blah', 'token', 'token_secret', string);
          assert.equal(called, true);
          done();
        });

        it('should write content-type as defined, with content-length specified', function (done) {
          var oa = new OAuth({
            requestUrl: 'http://term.ie/oauth/example/request_token.php',
            accessUrl: 'http://term.ie/oauth/example/access_token.php',
            consumerKey: 'key',
            consumerSecret: 'secret',
            version: '1.0A',
            signatureMethod: OAuth.signatures.hmac
          }), string = "foo=1%2C2%2C3&bar=1%2B2", stringLength = string.length, stringByteLength = Buffer.byteLength(string), called = false;

          oa.createClient = function (options) {
            assert.equal(options.headers['Content-Type'], 'unicorn/encoded');
            assert.equal(options.headers['Content-Length'], stringByteLength);
            return {
              write: function (data) {
                called = true;
                assert.equal(data, string);
              },
              on: function () {},
              end: function () {}
            };
          };

          var request = oa.post('http://foo.com/blah', 'token', 'token_secret', string, 'unicorn/encoded');
          assert.equal(called, true);
          done();
        });
      });

      it('should support passing object rather than individual parameters', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          signatureMethod: OAuth.signatures.hmac
        }), string = "foo=1%2C2%2C3&bar=1%2B2", stringLength = string.length, stringByteLength = Buffer.byteLength(string), called = false;

        oa.createClient = function (options) {
          assert.equal(options.headers['Content-Type'], 'unicorn/encoded');
          assert.equal(options.headers['Content-Length'], stringByteLength);
          return {
            write: function (data) {
              called = true;
              assert.equal(data, string);
            },
            on: function () {},
            end: function () {}
          };
        };

        var request = oa.post({
          url: 'http://foo.com/blah',
          oauth_token: 'token',
          oauth_token_secret: 'token_secret',
          body: string,
          type: 'unicorn/encoded'
        });

        assert.equal(called, true);
        done();
      });
    });

    describe('Request with Callback', function () {
      it('should callback successfully on a 200 response code', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          signatureMethod: OAuth.signatures.hmac
        }), called = false;

        oa.createClient = function (options) {
          return new FakeRequest(new FakeResponse(200));
        };

        var request = oa.performSecureRequest({
          method: "POST",
          url: 'http://foo.com/blah',
          oauth_token: 'token',
          oauth_token_secret: 'token_secret',
          parameters: { "scope": "foobar,1,2" },
          type: 'unicorn/encoded',
          callback: function (error) {
            called = true;
            assert.equal(error, undefined);
          }
        });

        assert.equal(called, true);
        done();
      });

      it('should callback successfully on a 210 response code', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          signatureMethod: OAuth.signatures.hmac
        }), called = false;

        oa.createClient = function (options) {
          return new FakeRequest(new FakeResponse(210));
        };

        var request = oa.performSecureRequest({
          method: "POST",
          url: 'http://foo.com/blah',
          oauth_token: 'token',
          oauth_token_secret: 'token_secret',
          parameters: { "scope": "foobar,1,2" },
          callback: function (error) {
            called = true;
            assert.equal(error, undefined);
          }
        });

        assert.equal(called, true);
        done();
      });

      it('should execute callback, passing response code if no location header exists', function (done) {
        var oa = new OAuth({
          requestUrl: 'http://term.ie/oauth/example/request_token.php',
          accessUrl: 'http://term.ie/oauth/example/access_token.php',
          consumerKey: 'key',
          consumerSecret: 'secret',
          version: '1.0A',
          signatureMethod: OAuth.signatures.hmac
        }), called = false;

        oa.createClient = function (options) {
          return new FakeRequest(new FakeResponse(301));
        };

        var request = oa.performSecureRequest({
          method: "POST",
          url: 'http://foo.com/blah',
          oauth_token: 'token',
          oauth_token_secret: 'token_secret',
          parameters: { "scope": "foobar,1,2" },
          callback: function (error) {
            called = true;
            assert.equal(error.statusCode, 301);
          }
        });

        assert.equal(called, true);
        done();
      });
    });
  });
});