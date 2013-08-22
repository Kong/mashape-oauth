var crypto = require('crypto');
var http = require('http');
var https = require('https');
var URL = require('url');
var query = require('querystring');
var utils = require('./utils');
var zlib = require('zlib');

// Constructor for starting an OAuth (1.0) handshake
//
// - `options` `Object` *OAuth request options*
//   - `echo` `Object` ___Optional___ *If it exists we treat the request as OAuth Echo request. See [Twitter](https://dev.twitter.com/docs/auth/oauth/oauth-echo)*
//       - `verifyCredentials` `String` *What is the credentials URI to delegate against?*
//   - `realm` `String` ___Optional___ *Access Authentication Framework Realm Value, Commonly used in Echo Requests, allowed in all however: [Section 3.5.1](http://tools.ietf.org/html/rfc5849#section-3.5.1)*
//   - `requestUrl` `String` *Request Token URL. [Section 6.1](http://oauth.net/core/1.0/#auth_step1)*
//   - `accessUrl` `String` *Access Token URL. [Section 6.2](http://oauth.net/core/1.0/#auth_step2)*
//   - `callback` `String` *URL the Service Provider will use to redirect User back to Consumer after obtaining User Authorization has been completed. [Section 6.2.1](http://oauth.net/core/1.0/#auth_step2)*
//   - `consumerKey` `String` *The Consumer Key*
//   - `consumerSecret` `String` *The Consumer Secret*
//   - `version` `String` ___Optional___ *By spec this is `1.0` by default. [Section 6.3.1](http://oauth.net/core/1.0/#auth_step3)*
//   - `signatureMethod` `String` *Type of signature to generate, must be one of:*
//       - PLAINTEXT
//       - RSA-SHA1
//       - HMAC-SHA1
//   - `nonceLength` `Number` ___Optional___ *Length of nonce string. Default `32`*
//   - `headers` `Object` ___Optional___ *Headers to be sent along with request, by default these are already set.*
//   - `clientOptions` `Object` ___Optional___ *Contains `requestTokenHttpMethod` and `accessTokenHttpMethod` value.*
//   - `parameterSeperator` `String` ___Optional___ *Seperator for OAuth header parameters. Default is `,`*
//
// Example: (javascript)
//
//     var OAuth = require('mashape-oauth').OAuth;
//     var oa = new OAuth({ /* ... options ... */ }, callback);
//
var OAuth = module.exports = exports = function (options) {
  options = options || {};

  if (options.echo) {
    this.echo = true;
    this.verifyCredentials = options.echo.verifyCredentials;
  } else {
    this.echo = false;
    this.requestUrl = options.requestUrl;
    this.accessUrl = options.accessUrl;
    this.authorizeCallback = options.callback ? options.callback : "oob";
  }

  this.realm = options.realm || undefined;
  this.consumerKey = options.consumerKey;
  this.consumerSecret = utils.encodeData(options.consumerSecret);
  this.version = options.version;
  this.signatureMethod = typeof options.signatureMethod === 'string' ? options.signatureMethod.toUpperCase() : undefined;
  this.nonceLength = options.nonceLength || options.nonceSize || 32;
  this.customTimestamp = options.timestamp || undefined;
  this.customNonce = options.nonce || undefined;

  if (this.signatureMethod !== OAuth.signatures.plaintext &&
      this.signatureMethod !== OAuth.signatures.hmac &&
      this.signatureMethod !== OAuth.signatures.rsa)
    throw new Error("Un-supported signature method: " + this.signatureMethod);

  if (this.signatureMethod === OAuth.signatures.rsa)
    this.privateKey = options.consumerSecret;

  this.headers = options.headers || {
    "Accept": "*/*",
    "Connection": "close",
    "User-Agent": "Gatekeeper-OAUTH"
  };

  this.clientOptions = options.clientOptions || {
    "requestTokenHttpMethod": "POST",
    "accessTokenHttpMethod": "POST"
  };

  this._clientOptions = this.clientOptions;
  this.parameterSeperator = options.parameterSeperator || ",";
};

OAuth.prototype.setClientOptions = function (options) {
  this.clientOptions = utils.extend(this._clientOptions, options);
};

// OAuth 1.0 Signature Enum
OAuth.signatures = {
  plaintext: "PLAINTEXT",
  hmac: "HMAC-SHA1",
  rsa: "RSA-SHA1"
};

// Calculates current timestamp in seconds.
// Utilizes flooring to prevent being sent too soon.
OAuth.getTimestamp = function () {
  return Math.floor((new Date()).getTime() / 1000);
};

// Generates randomized string of a certain length given a character table.
//
// - `length` `Number` ___Optional___ *Size of string in character length. Default `32`*
//
// Example: (javascript)
//
//    var nonce = OAuth.nonce();
//
OAuth.nonce = function (length) {
  var result = [], i = 0; length = length || 32;
  for (i; i < length; i++)
    result.push(OAuth.nonce.chars[Math.floor(Math.random() * OAuth.nonce.chars.length)]);
  return result.join('');
};

// Nonce Character Table.
// By Default this character table is `a-zA-Z0-9`.
OAuth.nonce.chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

// Sorts tuple array by key (0), then value (1) when keys (0) are equal (non-strict).
//
// - `tuple` `Array`
//
// Return: `Array`
OAuth.tupleSorter = function (tuple) {
  tuple.sort(function (a, b) {
    if (a[0] == b[0]) return a[1] < b[1] ? -1 : 1;
    else return a[0] < b[0] ? -1 : 1;
  });

  return tuple;
};

// Takes an object of key-value store and converts each item into a tuple.
// If they value of a key is an array we iterate upon it creating multiple tuples of that key.
//
// Example: (javascript)
//
//     // Would become: [["hello", "world"], ["name", "woah"], ["array", 1], ["array", 2], ["array", 3]];
//     var tuple = OAuth.tupleArguments({ "hello": "world", "name": "woah", "array": [1,2,3] });
//
// Return: `Array`
OAuth.tupleArguments = function (args) {
  var tuple = [], i = 0, key, value;

  for (key in args) {
    if (!args.hasOwnProperty(key)) continue;
    value = args[key];

    if (Array.isArray(value))
      for (i; i < value.length; i++)
        tuple.push([key, value[i]]);
    else
      tuple.push([key, value]);
  }

  return tuple;
};

// Normalizes argument object. First by tupling, encoding & sorting the tuples, and
// finally creating a psuedo-query string of key-value information from the tupled array.
//
// Example: (javascript)
//
//     // Would become: array=1&array=2&array=3&hello=world&name=woah
//     var tuple = OAuth.tupleArguments({ "hello": "world", "name": "woah", "array": [1,2,3] });
//
// Return: `String`
OAuth.normalizeArguments = function (args) {
  var tuple = OAuth.tupleArguments(args), i = 0, output = "";

  for (i; i < tuple.length; i++)
    tuple[i][0] = utils.encodeData(tuple[i][0]),
    tuple[i][1] = utils.encodeData(tuple[i][1]);

  tuple = OAuth.tupleSorter(tuple);

  for (i = 0; i < tuple.length; i++)
    output += tuple[i][0] + "=" + tuple[i][1] + ((i < tuple.length-1) ? "&" : "");

  return output;
};

// Formats and normalizes url port, protocol and slashes.
//
// - `url` `String` URL to be normalized
//
// Return: `String`
OAuth.normalizeUrl = function (url) {
  var parsed = URL.parse(url, true), port = "";

  if (parsed.port)
    if ((parsed.protocol === 'http:' && parsed.port != '80') || (parsed.protocol === 'https:' && parsed.port != '443'))
      port = ":" + parsed.port;

  return parsed.protocol + "//" + parsed.hostname + port + ((!parsed.pathname || parsed.pathname === "") ? "/" : parsed.pathname);
};

// Details whether given parameter is a direct oauth parameter or not.
// We can tell this by checking whether the parameter begins with `oauth_` or not.
//
// - `parameter` `String` *Parameter name or key name*
//
// Return: `Boolean`
OAuth.isOAuthParameter = function (parameter) {
  var match = parameter.match('^oauth_');
  return (match && (match[0] === "oauth_"));
};

// Generates signature by creating the signature base first then delegating the information to `createSignature`.
//
// Return: `String`
OAuth.prototype.getSignature = function (options) {
  return this.createSignature(this.createSignatureBase(options.method, options.url, options.parameters), options.token_secret);
};

// Encodes and normalizes url, parameters, then joins them together with the `&` char, in ordinance of arguments.
//
// - `method` `String` *Request method*
// - `url` `String` *URL being utilized in request*
// - `parameters` `String` *Tupled, encoded and normalized parameters list*
//
// Return: `String`
OAuth.prototype.createSignatureBase = function (method, url, parameters) {
  url = utils.encodeData(OAuth.normalizeUrl(url));
  parameters = utils.encodeData(parameters);
  return method.toUpperCase() + "&" + url + "&" + parameters;
};

// Generates signature by hashing against the base using a key made up of the consumer secret and token secret.
//
// - `base` `String` *Joint string, made up of request method, url, and parameters.*
// - `token_secret` `String`
//
// Return: `String`
OAuth.prototype.createSignature = function (base, token_secret) {
  token_secret = (token_secret === undefined) ? "" : utils.encodeData(token_secret);
  var key = this.consumerSecret + "&" + token_secret;

  if (this.signatureMethod === OAuth.signatures.plaintext)
    return key;
  else if (this.signatureMethod === OAuth.signatures.rsa)
    return crypto.createSign("RSA-SHA1").update(base).sign(this.privateKey || "", 'base64');
  else if (crypto.Hmac)
    return crypto.createHmac("sha1", key).update(base).digest('base64');
  else
    return utils.SHA1.hmacSha1(key, base);
};

OAuth.prototype.createClient = function (options) {
  return ((options.ssl) ? https : http).request(options);
};

OAuth.prototype.buildAuthorizationHeaders = function (parameters) {
  var header = 'OAuth ', realm, i = 0;
  for (i; i < parameters.length; i++) if (parameters[i][0] === "realm") realm = parameters[i][1];
  if (realm || this.realm) header += 'realm="' + (realm || this.realm) + '",';

  for (i = 0; i < parameters.length; i++)
    if (OAuth.isOAuthParameter(parameters[i][0]))
      header += '' + utils.encodeData(parameters[i][0]) + '="' + utils.encodeData(parameters[i][1]) + '"' + this.parameterSeperator;

  return header.substring(0, header.length - this.parameterSeperator.length);
};

OAuth.prototype.buildAuthorizationQuery = function (parameters) {
  var query = "", realm, i = 0;

  for (i; i < parameters.length; i++) 
    if (parameters[i][0] === "realm") 
      realm = parameters[i][1];

  if (realm || this.realm) 
    query += 'realm=' + (realm || this.realm) + '&';

  for (i = 0; i < parameters.length; i++)
    query += utils.encodeData(parameters[i][0]) + '=' + utils.encodeData(parameters[i][1]) + '&';

  return query.substring(0, query.length-1);
};

OAuth.prototype.prepareParameters = function (options) {
  var parameters = {}, signature = {}, parsed, key, value, extras, sorted;

  if (typeof options.body === "string") {
    try {
      parameters = JSON.parse(options.body);
    } catch (e) {
      if (typeof query.parse(options.body) === "object")
        parameters = utils.extend(parameters, query.parse(options.body));
    }
  }

  parameters.oauth_timestamp = typeof this.customTimestamp === 'function' ? this.customTimestamp() : OAuth.getTimestamp();
  parameters.oauth_nonce = typeof this.customNonce === 'function' ? this.customNonce(this.nonceLength) : OAuth.nonce(this.nonceLength);
  parameters.oauth_version = this.version;
  parameters.oauth_signature_method = this.signatureMethod;
  parameters.oauth_consumer_key = this.consumerKey;

  if (typeof options.oauth_token !== 'undefined')
    parameters.oauth_token = options.oauth_token;

  if (this.echo)
    signature = { 
      method: "GET", 
      url: this.verifyCredentials, 
      parameters: OAuth.normalizeArguments(parameters) 
    };
  else {
    if (options.parameters)
      for (key in options.parameters)
        if (options.parameters.hasOwnProperty(key))
          parameters[key] = options.parameters[key];

    parsed = URL.parse(options.url, false);

    if (parsed.query)
      extras = query.parse(parsed.query),
      parameters = utils.serialExtend(parameters, extras);

    signature = { method: options.method, url: options.url, parameters: OAuth.normalizeArguments(parameters) };
  }

  if (options.oauth_token_secret || options.token_secret)
    signature.token_secret = options.oauth_token_secret || options.token_secret;

  sorted = OAuth.tupleSorter(OAuth.tupleArguments(parameters));
  sorted.push(["oauth_signature", this.getSignature(signature)]);

  return sorted;
};

// Correctly handles and parses information required for an OAuth Request
//
// - `options` `Object`
//    - `oauth_token` `String` ___Required___
//    - `oauth_token_secret` `String` ___Required___
//    - `type` `String` *Content Type*
//    - `method` `String` *Request Method Type*
//    - `realm` `String` *Realm for Echo request or basic request*
//    - `url` `String` *Request location*
//    - `parameters` `Object` *Extra parameters for body*
//    - `body` `Mixed`
//
OAuth.prototype.performSecureRequest = function (options, callback) {
  var $this = this, sorted, parsed, data, type = false, headers = {}, request, key, path;
  options.type = options.type || "application/x-www-form-urlencoded";
  options.method = options.method.toUpperCase();
  options.realm = options.realm || this.realm || undefined;
  sorted = this.prepareParameters(options);
  callback = callback || options.callback;
  parsed = URL.parse(options.url, false);
  parsed.port = parsed.port || (parsed.protocol === 'http:' ? 80 : 443);
  if (this.echo) headers["X-Auth-Service-Provider"] = this.verifyCredentials;
  headers[(this.echo) ? "X-Verify-Credentials-Authorization" : "Authorization"] = this.buildAuthorizationHeaders(sorted);
  headers.Host = parsed.host;
  headers = utils.extend(headers, this.headers);

  for (key in options.parameters)
    if (options.parameters.hasOwnProperty(key))
      if (OAuth.isOAuthParameter(key))
        delete options.parameters[key];

  if ((options.method === "POST" || options.method === "PUT") && (!options.body && options.parameters))
    options.body = query.stringify(options.parameters).
      replace(/\!/g, "%21").
      replace(/\'/g, "%27").
      replace(/\(/g, "%28").
      replace(/\)/g, "%29").
      replace(/\*/g, "%2A");

  if (this.clientOptions.accessTokenHttpMethod === 'GET' && options.url === this.accessUrl) {
    delete headers.Authorization;
    parsed.query = this.buildAuthorizationQuery(sorted);
  }

  headers["Content-Length"] = options.body ? Buffer.isBuffer(options.body) ? options.body.length :  Buffer.byteLength(options.body) : 0;
  headers["Content-Type"] = options.type;

  if (!parsed.pathname || parsed.pathname === "") parsed.pathname = "/";
  if (parsed.query) path = parsed.pathname + "?" + parsed.query;
  else path = parsed.pathname;

  request = this.createClient({
    port: parsed.port,
    host: parsed.hostname,
    path: path,
    method: options.method,
    headers: headers,
    ssl: (parsed.protocol === 'https:')
  });

  if (callback) {
    var earlyClose = utils.isAnEarlyCloseHost(parsed.hostname), called = false;

    var respond = function (response) {
      if (type === 2) data = data.toString('utf8');
      if (called) return; else called = true;
      if (response.statusCode >= 200 && response.statusCode <= 299)
        callback(null, data, response);
      else if ((response.statusCode == 301 || response.statusCode == 302) && response.headers && response.headers.location) {
        options.url = response.headers.location,
        $this.performSecureRequest(options, callback);
      } else
        callback({ 
          statusCode: response.statusCode, 
          data: data 
        }, data, response);
    };

    request.on('response', function (response) {
      var output;

      if ($this.clientOptions.detectResponseContentType && utils.isBinaryContent(response)) {
        data = new Buffer(0);
        type = 1;
        output = response;
      } else if (response.headers['content-encoding'] === 'gzip') {
        var gunzip = zlib.createGunzip();
        data = new Buffer(0);
        type = 2;
        response.pipe(gunzip);
        output = gunzip;
      } else {
        response.setEncoding('utf8');
        data = "";
        output = response;
      }

      output.on('data', function (chunk) { 
        if (type === 1 || type === 2) data = Buffer.concat([data, chunk]);
        else data += chunk;
      });

      output.on('close', function () { 
        if (earlyClose) respond(response); 
      });

      output.on('end', function () { 
        respond(response);
      });
    });

    request.on('error', function (error) {
      called = true; callback(error); 
    });

    if ((options.method === "POST" || options.method === "PUT") && (options.body && options.body !== ""))
      request.write(options.body);

    request.end();
  } else {
    if ((options.method === "POST" || options.method === "PUT") && (options.body && options.body !== ""))
      request.write(options.body);

    return request;
  }

  return;
};

OAuth.prototype.handleRequest = function (options, callback) {
  return this.performSecureRequest(options, callback);
};

OAuth.prototype.handleRequestLong = function (url, method, token, secret, body, type, parameters, callback) {
  return this.handleRequest({
    url: url,
    method: method,
    oauth_token: token || undefined,
    oauth_token_secret: secret,
    body: body,
    type: type,
    parameters: typeof parameters === 'function' ? undefined : parameters
  }, typeof parameters === 'function' ? parameters : callback);
};

[ 'delete', 'put', 'post', 'get', 'patch' ].forEach(function (k, i) {
  OAuth.prototype[k] = function (url, token, secret, body, type, parameters, callback) {
    if (typeof token === 'function' || typeof url === 'object') { url.method = k.toUpperCase(); return this.handleRequest(url, token);
    } else return this.handleRequestLong(url, k.toUpperCase(), token, secret, body, type, parameters, callback);
  };
});

// Create & handles Access Token call while extracting information from response such as Token and Secret.
//
// - `options` `Object`
//   - `oauth_verifier` `String` *Verification code tied to the Request Token. [Section 2.3](http://tools.ietf.org/html/rfc5849#section-2.3)*
//   - `oauth_token` `String` *Request Token*
//   - `oauth_token_secret` `String` *Request Token Secret, used to help generation of signatures.*
//   - `parameters` `Object` ___Optional___ *Additional headers to be sent along with request.*
//   - `callback` `Function` ___Optional___ *Method to be invoked upon result, over-ridden by argument if set.*
// - `callback` `Function` *Anonymous Function to be invoked upon response or failure, setting this overrides previously set callback inside options object.*
//
// Example: (javascript)
//
//     oa.getOAuthRequestToken({/* ... Parameters ... */}, callback);
//
OAuth.prototype.getOAuthAccessToken = function (options, callback) {
  callback = options.callback || callback;
  options.parameters = options.parameters || {};

  if (options.oauth_verifier)
    options.parameters.oauth_verifier = options.oauth_verifier,
    delete options.oauth_verifier;

  options.method = this.clientOptions.accessTokenHttpMethod;
  options.url = this.accessUrl;
  options.body = null;
  options.type = null;

  this.performSecureRequest(options, function (error, data, response) {
    if (error) return callback(error);
    var results = query.parse(data), token = results.oauth_token, secret = results.oauth_token_secret;
    delete results.oauth_token; delete results.oauth_token_secret;
    callback(null, token, secret, results);
  });
};

// Create & handles Request Token call while extracting information from response such as Token and Secret.
//
// - `parameters` `Object` ___Optional___ *Additional Headers you might want to pass along.*
//   - *If omitted, you can treat parameters argument as callback and pass along a function as a single parameter.*
// - `callback` `Function` *Anonymous Function to be invoked upon response or failure.*
//
// Example: (javascript)
//
//     oa.getOAuthRequestToken({/* ... Parameters ... */}, callback);
//
OAuth.prototype.getOAuthRequestToken = function (parameters, callback) {
  if (typeof parameters === 'function')
    callback = parameters, parameters = {};

  if (this.authorizeCallback)
    parameters.oauth_callback = this.authorizeCallback;

  this.handleRequestLong(this.requestUrl, this.clientOptions.requestTokenHttpMethod, null, null, null, null, parameters, function (error, data, response) {
    if (error) return callback(error);
    var results = query.parse(data), token = results.oauth_token, secret = results.oauth_token_secret;
    delete results.oauth_token; delete results.oauth_token_secret;
    callback(null, token, secret, results);
  });
};

OAuth.prototype.getXAuthAccessToken = function (username, password, permissions, callback) {
  if (typeof permissions === 'function')
    callback = permissions, permissions = undefined;

  var parameters = { 'x_auth_mode': 'client_auth', 'x_auth_password': password, 'x_auth_username': username };

  if (permissions)
    parameters.x_auth_permission = permissions;

  this.handleRequestLong(this.accessUrl, this.clientOptions.accessTokenHttpMethod, null, null, null, null, parameters, function (error, data, response) {
    var results = query.parse(data), token = results.oauth_token, secret = results.oauth_token_secret;
    delete results.oauth_token; delete results.oauth_token_secret;
    callback(null, token, secret, results);
  });
};

OAuth.prototype.signUrl = function (url, token, secret, method) {
  var ordered, parsed = URL.parse(url, false), i = 0, query = "";
  ordered = this.prepareParameters({ url: url, oauth_token: token, oauth_token_secret: secret, method: method || "GET" });
  for (i; i < ordered.length; i++) query += ordered[i][0] + "=" + utils.encodeData(ordered[i][1]) + "&";
  return parsed.protocol + "//" + parsed.host + parsed.pathname + "?" + query.substring(0, query.length-1);
};

OAuth.prototype.authHeader = function (options) {
  return this.buildAuthorizationHeaders(this.prepareParameters({ 
    url: options.url, 
    oauth_token: options.token, 
    oauth_token_secret: options.secret, 
    method: options.method || "GET",
    body: options.body
  }));
};