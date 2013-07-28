var crypto = require('crypto');
var http = require('http');
var https = require('https');
var URL = require('url');
var query = require('querystring');
var utils = require('./utils');

// Initializer for Creating an OAuth (2.0) Request
//
// - options {Object} OAuth Request Options
//   - clientId {String} Client Identifier
//   - clientSecret {String} Client Secret
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
  args.type = 'web_server';
  return (this.authorizationUrl.indexOf('http') != -1 ? this.authorizationUrl : this.baseUrl + this.authorizationUrl) + "?" + query.stringify(args);
};

OAuth2.prototype.getAccessTokenUrl = function () {
  return (this.accessTokenUrl.indexOf('http') != -1 ? this.accessTokenUrl : this.baseUrl + this.accessTokenUrl);
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
  var credentials = crypto.createCredentials({}), parsed = URL.parse(options.url), path, headers;
  callback = options.callback || callback;
  options.method = options.method.toUpperCase();
  parsed.port = parsed.port || (parsed.protocol === 'http:' ? 80 : 443);
  headers = utils.extend(this.headers, options.headers || {});
  headers.Host = parsed.host;
  headers["Content-Length"] = options.body ? Buffer.isBuffer(options.body) ? options.body.length : Buffer.byteLength(options.body) : 0;

  if (!parsed.pathname || parsed.pathname === "")
    parsed.pathname = "/";

  if (options.access_token && !('Authorization' in headers))
    (parsed.query = parsed.query || {})[this.accessTokenName] = options.access_token;

  if (parsed.query) path = parsed.pathname + "?" + query.stringify(parsed.query);
  else path = parsed.pathname;

  this.executeRequest({
    host: parsed.hostname,
    port: parsed.port,
    path: path,
    method: options.method,
    headers: headers,
    body: options.body,
    ssl: (parsed.protocol === 'https:')
  }, callback);
};

OAuth2.prototype.executeRequest = function (options, callback) {
  var $this = this, request = this.createClient(options), respond, closesEarly, called = false, data;
  closesEarly = utils.isAnEarlyCloseHost(options.host);

  respond = function (response) {
    if (called) return; else called = true;
    if (response.statusCode >= 200 && response.statusCode <= 299)
      callback(null, data, response);
    else
      callback({ statusCode: response.statusCode, data: data }, data, response);
  };

  request.on('response', function (response) {
    binary = false;

    if ($this.detectResponseContentType && utils.isBinaryContent(response)) {
      data = new Buffer(0);
      binary = true;
    } else {
      response.setEncoding('utf8');
      data = "";
    }

    response.on('data', function (chunk) { if (binary) data = Buffer.concat([data, chunk]); else data += chunk; });
    response.on('close', function () { if (closesEarly) respond(response); });
    response.on('end', function () { respond(response); });
  });

  request.on('error', function (error) {
    called = true;
    callback(error);
  });

  if (options.method === 'POST' && options.body)
    request.write(options.body);

  request.end();
};

OAuth2.prototype.getOAuthAccessToken = function (code, args, callback) {
  var param, data, headers;
  args = args || {};
  args.type = 'web_server';
  args[args.grant_type === 'refresh_token' ? 'refresh_token' : 'code'] = code;

  if (!('Authorization' in this.headers))
    args.client_id = this.clientId,
    args.client_secret = this.clientSecret;

  data = query.stringify(args);

  this.request({
    method: "POST",
    url: this.getAccessTokenUrl(),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: query.stringify(args)
  }, function (error, data, response) {
    if (error) return callback(error);
    var results, access, refresh;
    // http://tools.ietf.org/html/draft-ietf-oauth-v2-07 or Facebook & Github rev05
    try { results = JSON.parse(data); } catch (e) { results = query.parse(data); }
    access = results.access_token; refresh = results.refresh_token; delete results.refresh_token;
    callback(null, access, refresh, results);
  });
};

OAuth2.prototype.get = function (url, access_token, callback) {
  var headers = {};
  if (this.authorizationHeader) headers.Authorization = this.buildAuthHeader(access_token);
  this.request({ method: "GET", url: url, headers: headers, access_token: access_token}, callback);
};