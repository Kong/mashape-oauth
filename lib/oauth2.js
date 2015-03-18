var http = require('http');
var https = require('https');
var Url = require('url');
var query = require('querystring');
var utils = require('./utils');

// Initializer for Creating an OAuth (2.0) Request
//
// - options {Object} OAuth Request Options
//   - clientId {String} Client Identifier
//   - clientSecret {String} Client Secret
//   - username {String} Username
//   - password {String} Password
//   - baseUrl {String} Base url of OAuth request
//   - authorizationUrl {String} Optional; Authorization endpoint, default is `/oauth/authorize`
//   - authorizationMethod {String} Optional; Authorization Header Method, default is `Bearer`
//   - accessTokenUrl {String} Optional; Access Token Endpoint, default is `/oauth/access_token`
//   - accessTokenName {String} Optional; Access Token Parameter Name, default is `access_token`
//   - headers {Object} Optional; Custom headers we wish to pass along
var OAuth2 = module.exports = exports = function (options) {
  options = options || {};

  this.clientId = options.clientId;
  this.clientSecret = options.clientSecret;
  this.baseUrl = options.baseUrl;
  this.authorizationUrl = options.authUrl || "/oauth/authorize";
  this.authorizationMethod = options.authMethod || "Bearer";
  this.accessTokenUrl = options.accessTokenUrl || "/oauth/access_token";
  this.accessTokenName = options.accessTokenName || "access_token";
  this.headers = options.headers || {};
  this.authorizationHeader = false;
  this.detectResponseContentType = options.detectResponseContentType;
};

OAuth2.prototype.getAuthorizeUrl = function (args) {
  args = args || {};
  args.client_id = this.clientId;

  if (args.type === null) {
    delete args.type;
  } else {
    args.type = args.type || 'web_server';
  }

  return (this.authorizationUrl.indexOf('http') !== -1 ? this.authorizationUrl : this.baseUrl + this.authorizationUrl) + "?" + query.stringify(args);
};

OAuth2.prototype.getAccessTokenUrl = function () {
  return (this.accessTokenUrl.indexOf('http') !== -1 ? this.accessTokenUrl : this.baseUrl + this.accessTokenUrl);
};

OAuth2.prototype.buildAuthHeader = function (token) {
  return this.authorizationMethod + ' ' + token;
};

OAuth2.prototype.useAuthHeaderForGet = function (value) {
  this.authorizationHeader = typeof value !== 'undefined' ? value : true;
};

OAuth2.prototype.createClient = function (options) {
  return ((options.ssl) ? https : http).request(options);
};

OAuth2.prototype.request = function (options, callback) {
  var self = this;
  var parsed = Url.parse(options.url);
  var headers = utils.extend(this.headers, options.headers || {});
  var settings;
  var path;

  // Set callback
  callback = options.callback || callback;

  // Ensure method is always uppercase
  options.method = options.method.toUpperCase();

  // Ensure port from parsing takes higher priority over inferred
  parsed.port = parsed.port || (parsed.protocol === 'http:' ? 80 : 443);

  // Setup Headers
  headers["Host"] = parsed.host;
  headers["Content-Length"] = options.body ? Buffer.isBuffer(options.body) ? options.body.length : Buffer.byteLength(options.body) : 0;

  // Add mashape-oauth user-agent when no agent is specified
  if (!headers["User-Agent"]) {
    headers["User-Agent"] = "mashape-oauth";
  }

  // Pathname fallback to forwardslash
  if (!parsed.pathname || parsed.pathname === "") {
    parsed.pathname = "/";
  }

  // Add access token to querystring when Authorization header is missing
  if (options.access_token && !('Authorization' in headers)) {
    (parsed.query = parsed.query || {})[this.accessTokenName] = options.access_token;
  }

  // Rebuild path from parsed values
  path = parsed.query ? parsed.pathname + "?" + query.stringify(parsed.query) : parsed.pathname;

  // Create options hash
  settings = {
    host: parsed.hostname,
    port: parsed.port,
    path: path,
    method: options.method,
    headers: headers,
    body: options.body,
    ssl: (parsed.protocol === 'https:'),
    agent: options.agent
  };

  // Allow for tls.connect options
  // https://nodejs.org/api/https.html#https_https_request_options_callback
  if (settings.ssl) {
    settings.pfx = options.pfx;
    settings.key = options.key;
    settings.cert = options.cert;

    if (typeof options.ca !== 'undefined') {
      settings.ca = options.ca;
    }

    if (typeof options.ciphers !== 'undefined') {
      settings.ciphers = options.ciphers;
    }

    if (typeof options.rejectUnauthorized !== 'undefined') {
      settings.rejectUnauthorized = options.rejectUnauthorized;
    }

    if (typeof options.secureProtocol !== 'undefined') {
      settings.secureProtocol = options.secureProtocol;
    }
  }

  // Fix timing issue in specific version of io.js
  // https://github.com/iojs/io.js/issues/712#issuecomment-72883863
  //
  // process.nextTick -- doesn't work
  // setInterval -- doesn't work
  setTimeout(function () {
    self.executeRequest(settings, callback);
  }, 0);
};

OAuth2.prototype.executeRequest = function (options, callback) {
  var self = this;
  var called = false;
  var request = this.createClient(options);
  var closesEarly = utils.isAnEarlyCloseHost(options.host);
  var data;

  function respond (response) {
    if (called) {
      return;
    } else {
      called = true;
    }

    if (response.statusCode >= 200 && response.statusCode <= 299) {
      callback(null, data, response);
    } else {
      callback({ statusCode: response.statusCode, data: data }, data, response);
    }
  }

  request.on('response', function (response) {
    var binary = false;

    if (self.detectResponseContentType && utils.isBinaryContent(response)) {
      data = new Buffer(0);
      binary = true;
    } else {
      response.setEncoding('utf8');
      data = "";
    }

    response.on('data', function (chunk) {
      if (binary) {
        data = Buffer.concat([data, chunk]);
      } else {
        data += chunk;
      }
    });

    response.on('close', function () {
      if (closesEarly) {
        respond(response);
      }
    });

    response.on('end', function () {
      respond(response);
    });
  });

  request.on('error', function (error) {
    called = true;
    callback(error);
  });

  if (options.method === 'POST' && options.body) {
    request.write(options.body);
  }

  request.end();
};

OAuth2.prototype.getOAuthAccessToken = function (code, args, callback) {
  var data;

  args = args || {};

  if (args.type === null) {
    delete args.type;
  } else {
    args.type = args.type || 'web_server';
  }

  // Grant type
  args[args.grant_type || 'code'] = code;

  // Add authorization when Authorization header doesn't exist
  if (!('Authorization' in this.headers)) {
    args.client_id = this.clientId;

    if (args.grant_type === 'password') {
      args.username = args.username || this.username;
      args.password = args.password || this.password;
    } else {
      args.client_secret = this.clientSecret;
    }
  }

  // Stringify arguments
  data = query.stringify(args);

  // Invoke request
  this.request({
    method: "POST",
    url: this.getAccessTokenUrl(),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: query.stringify(args)
  }, function (error, data) {
    if (error) {
      return callback(error);
    }

    var results;
    var access;
    var refresh;

    try {
      // Responses *should* be in JSON Format
      // http://tools.ietf.org/html/draft-ietf-oauth-v2-07
      results = JSON.parse(data);
    } catch (e) {
      // Facebook and Github use rev05 of the specification.
      // Both incorrectly specify content-type and suffer *minor* performance issues
      // due to dual parsing.
      results = query.parse(data);
    }

    access = results.access_token; refresh = results.refresh_token;
    delete results.refresh_token;

    callback(null, access, refresh, results);
  });
};

OAuth2.prototype.get = function (url, access_token, callback) {
  var headers = {};

  if (this.authorizationHeader) {
    headers.Authorization = this.buildAuthHeader(access_token);
  }

  this.request({
    method: "GET",
    url: url,
    headers: headers,
    access_token: access_token
  }, callback);
};

OAuth2.prototype.post = function (url, access_token, params, callback) {
  var headers = {};
  var type = this.headers['Content-Type'] || 'application/json';
  var payload;

  // Ensure content-type
  headers['Content-Type'] = type;

  // Check authorization header
  if (this.authorizationHeader) {
    headers.Authorization = this.buildAuthHeader(access_token);
  }

  if (typeof params !== 'string') {
    if (type.indexOf('application/json') !== -1) {
      payload = JSON.stringify(params);
    } else if (type.indexOf('application/x-www-form-urlencoded') !== -1) {
      payload = query.stringify(params);
    } else {
      payload = params;
    }
  } else {
    payload = params;
  }

  this.request({
    method: "POST",
    url: url,
    headers: headers,
    body: payload,
    access_token: access_token
  }, callback);
};