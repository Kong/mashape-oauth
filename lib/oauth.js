var crypto = require('crypto');
var http = require('http');
var https = require('https');
var URL = require('url');
var query = require('querystring');
var utils = require('./utils');

// Initializer for Creating an OAuth (1.0) Request
//
// - options {Object} OAuth Request Options
// - options.echo {Object} Optional; If it exists we treat the request as an echo request. See [Twitter](https://dev.twitter.com/docs/auth/oauth/oauth-echo).
// - options.echo.verifyCredentials {String} What is the credentials URI to delegate against?
// - options.realm {String} Optional; Access Authentication Framework Realm Value, Commonly used in Echo Requests, allowed in all however:
//   [Section 3.5.1](http://tools.ietf.org/html/rfc5849#section-3.5.1)
// - options.requestUrl {String} Request Token URL, [Section 6.1](http://oauth.net/core/1.0/#auth_step1)
// - options.accessUrl {String} Access Token URL, [Section 6.2](http://oauth.net/core/1.0/#auth_step2)
// - options.callback {String} URL the Service Provider will use to redirect User back to Consumer after obtaining User Authorization has been completed.
//   [Section 6.2.1](http://oauth.net/core/1.0/#auth_step2)
// - options.consumerKey {String} The Consumer Key
// - options.consumerSecret {String} The Consumer Secret
// - options.version {String} Optional; By spec this is `1.0` by default. [Section 6.3.1](http://oauth.net/core/1.0/#auth_step3)
// - options.signatureMethod {String} Type of signature to generate, must be one of:
//   - PLAINTEXT
//   - RSA-SHA1
//   - HMAC-SHA1
// - options.nonceLength {Number} Optional; Length of nonce string. Default `32`
// - options.headers {Object} Optional; Headers to be sent along with request, by default these are already set.
// - options.clientOptions {Object} Optional; Contains `requestTokenHttpMethod` and `accessTokenHttpMethod` value.
// - options.parameterSeperator {String} Optional; Seperator for OAuth header parameters, default is `,`
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
  this.consumerSecret = OAuth.encodeData(options.consumerSecret);
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

OAuth.signatures = {
  plaintext: "PLAINTEXT",
  hmac: "HMAC-SHA1",
  rsa: "RSA-SHA1"
};

OAuth.getTimestamp = function () {
  return Math.floor((new Date()).getTime() / 1000);
};

OAuth.encodeData = function (data) {
  if (data === "" || !data) return "";
  return encodeURIComponent(data).replace(/\!/g, "%21").
    replace(/\'/g, "%27").
    replace(/\(/g, "%28").
    replace(/\)/g, "%29").
    replace(/\*/g, "%2A");
};

OAuth.decodeData = function (data) {
  if (data !== null) data = data.replace(/\+/g, ' ');
  return decodeURIComponent(data);
};

OAuth.nonce = function (length) {
  var result = [], i = 0;
  for (i; i < length; i++)
    result.push(OAuth.nonce.chars[Math.floor(Math.random() * OAuth.nonce.chars.length)]);
  return result.join('');
};

OAuth.nonce.chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

// Sorts encoded tuple pairs by key, then value
//
// - tuple {Array}
OAuth.tupleSorter = function (tuple) {
  tuple.sort(function (a, b) {
    if (a[0] == b[0]) return a[1] < b[1] ? -1 : 1;
    else return a[0] < b[0] ? -1 : 1;
  });

  return tuple;
};

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

OAuth.normalizeArguments = function (args) {
  var tuple = OAuth.tupleArguments(args), i = 0, output = "";

  for (i; i < tuple.length; i++)
    tuple[i][0] = OAuth.encodeData(tuple[i][0]),
    tuple[i][1] = OAuth.encodeData(tuple[i][1]);

  tuple = OAuth.tupleSorter(tuple);

  for (i = 0; i < tuple.length; i++)
    output += tuple[i][0] + "=" + tuple[i][1] + ((i < tuple.length-1) ? "&" : "");

  return output;
};

OAuth.normalizeUrl = function (url) {
  var parsed = URL.parse(url, true), port = "";

  if (parsed.port)
    if ((parsed.protocol === 'http:' && parsed.port != '80') || (parsed.protocol === 'https:' && parsed.port != '443'))
      port = ":" + parsed.port;

  return parsed.protocol + "//" + parsed.hostname + port + ((!parsed.pathname || parsed.pathname === "") ? "/" : parsed.pathname);
};

OAuth.isOAuthParameter = function (parameter) {
  var match = parameter.match('^oauth_');
  return (match && (match[0] === "oauth_"));
};

OAuth.prototype.getSignature = function (options) {
  return this.createSignature(this.createSignatureBase(options.method, options.url, options.parameters), options.token_secret);
};

OAuth.prototype.createSignatureBase = function (method, url, parameters) {
  url = OAuth.encodeData(OAuth.normalizeUrl(url));
  parameters = OAuth.encodeData(parameters);
  return method.toUpperCase() + "&" + url + "&" + parameters;
};

OAuth.prototype.createSignature = function (base, token_secret) {
  var key, hash;

  token_secret = (token_secret === undefined) ? "" : OAuth.encodeData(token_secret);
  key = this.consumerSecret + "&" + token_secret;

  if (this.signatureMethod === OAuth.signatures.plaintext)
    hash = key;
  else if (this.signatureMethod === OAuth.signatures.rsa)
    hash = crypto.createSign("RSA-SHA1").update(base).sign(this.privateKey || "", 'base64');
  else if (crypto.Hmac)
    hash = crypto.createHmac("sha1", key).update(base).digest('base64');
  else
    hash = OAuth.SHA1.hmacSha1(key, base);

  return hash;
};

OAuth.prototype.buildAuthorizationHeaders = function (parameters) {
  var header = 'OAuth ', realm, i = 0;
  for (i; i < parameters.length; i++) if (parameters[i][0] === "realm") realm = parameters[i][1];
  if (realm || this.realm) header += 'realm="' + (realm || this.realm) + '",';

  for (i = 0; i < parameters.length; i++)
    if (OAuth.isOAuthParameter(parameters[i][0]))
      header += '' + OAuth.encodeData(parameters[i][0]) + '="' + OAuth.encodeData(parameters[i][1]) + '"' + this.parameterSeperator;

  return header.substring(0, header.length - this.parameterSeperator.length);
};

OAuth.prototype.createClient = function (options) {
  return ((options.ssl) ? https : http).request(options);
};

OAuth.prototype.prepareParameters = function (options) {
  var parameters = {}, signature = {}, parsed, key, value, extras, sorted;
  parameters.oauth_timestamp = typeof this.customTimestamp === 'function' ? this.customTimestamp() : OAuth.getTimestamp();
  parameters.oauth_nonce = typeof this.customNonce === 'function' ? this.customNonce(this.nonceLength) : OAuth.nonce(this.nonceLength);
  parameters.oauth_version = this.version;
  parameters.oauth_signature_method = this.signatureMethod;
  parameters.oauth_consumer_key = this.consumerKey;

  if (options.oauth_token !== undefined)
    parameters.oauth_token = options.oauth_token;

  if (this.echo)
    signature = { method: "GET", url: this.verifyCredentials, parameters: OAuth.normalizeArguments(parameters) };
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

  if (options.oauth_token_secret)
    signature.token_secret = options.oauth_token_secret;

  sorted = OAuth.tupleSorter(OAuth.tupleArguments(parameters));
  sorted.push(["oauth_signature", this.getSignature(signature)]);

  return sorted;
};

// Performing a secure request
//
// - options.oauth_token {String} Required;
// - options.oauth_token_secret {String} Required;
// - options.type {String} Content Type
// - options.method {String} Request Method Type
// - options.realm {String} Realm for Echo request or basic request
// - options.url {String} Request location
// - options.parameters {Object} Extra parameters for body
// - options.body {Mixed}
OAuth.prototype.performSecureRequest = function (options, callback) {
  var $this = this, sorted, parsed, data, binary = false, headers = {}, request, key, path;
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
      if (called) return; else called = true;
      if (response.statusCode >= 200 && response.statusCode <= 299)
        callback(null, data, response);
      else if ((response.statusCode == 301 || response.statusCode == 302) && response.headers && response.headers.location)
        options.url = response.headers.location,
        $this.performSecureRequest(options, callback);
      else
        callback({ statusCode: response.statusCode, data: data }, data, response);
    };

    request.on('response', function (response) {
      if ($this.clientOptions.detectResponseContentType && utils.isBinaryContent(response))
        data = new Buffer(0), binary = true;
      else
        response.setEncoding('utf8'), data = "";

      response.on('data', function (chunk) { if (binary) data = Buffer.concat([data, chunk]); else data += chunk; });
      response.on('close', function () { if (earlyClose) respond(response); });
      response.on('end', function () { respond(response); });
    });

    request.on('error', function (error) { called = true; callback(error); });

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

OAuth.prototype.setClientOptions = function (options) {
  this.clientOptions = utils.extend(this._clientOptions, options);
};

OAuth.prototype.handleRequest = function (options, callback) {
  return this.performSecureRequest(options, callback);
};

OAuth.prototype.handleRequestLong = function (url, method, token, secret, body, type, parameters, callback) {
  return this.handleRequest({
    url: url,
    method: method,
    oauth_token: token,
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
    var token = results.oauth_token, secret = results.oauth_token_secret;
    delete results.oauth_token; delete results.oauth_token_secret;
    callback(null, token, secret, results);
  });
};

OAuth.prototype.getOAuthRequestToken = function (parameters, callback) {
  if (typeof parameters === 'function')
    callback = parameters, parameters = {};

  if (this.authorizeCallback)
    parameters.oauth_callback = this.authorizeCallback;

  this.handleRequestLong(this.requestUrl, this.clientOptions.requestTokenHttpMethod, null, null, null, null, parameters, function (error, data, response) {
    if (error) return callback(error);
    var token = results.oauth_token, secret = results.oauth_token_secret;
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
    if (error) return callback(error);
    var results = query.parse(data), token = results.oauth_token, secret = results.oauth_token_secret;
    delete results.oauth_token; delete results.oauth_token_secret;
    callback(null, token, secret, results);
  });
};

OAuth.prototype.signUrl = function (url, token, secret, method) {
  var ordered, parsed = URL.parse(url, false), i = 0, query = "";
  ordered = this.prepareParameters({ url: url, oauth_token: token, oauth_token_secret: secret, method: method || "GET" });
  for (i; i < ordered.length; i++) query += ordered[i][0] + "=" + OAuth.encodeData(ordered[i][1]) + "&";
  return parsed.protocol + "//" + parsed.host + parsed.pathname + "?" + query.substring(0, query.length-1);
};

OAuth.prototype.authHeader = function (url, token, secret, method) {
  if (method === undefined) method = "GET";
  return this.buildAuthorizationHeaders(this.prepareParameters({ url: url, oauth_token: token, oauth_token_secret: secret, method: method || "GET" }));
};