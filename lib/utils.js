var utils = module.exports = exports = {
  SHA1: require('./sha1')
};

// Extend existing objects without creating references
utils.extend = function (original, context) {
  var output = JSON.parse(JSON.stringify(original || {})), key;
  for (key in context)
    if (context.hasOwnProperty(key))
      if (Object.prototype.toString.call(context[key]) === '[object Object]')
        output[key] = utils.extend(output[key] || {}, context[key]);
      else
        output[key] = context[key];
  return output;
};

// Extend objects and convert them to a serialized query string
utils.serialExtend = function (original, context, prefix) {
  var output = JSON.parse(JSON.stringify(original || {})), i, key, value;
  for (i in context) {
    if (!context.hasOwnProperty(i)) continue;
    else key = prefix ? prefix + "[" + i + "]" : i, value = context[i];
    if (Object.prototype.toString.call(value) === '[object Object]')
      output = utils.serialExtend(output, value, key);
    else
      output[key] = value;
  }
  return output;
};

// Determines whether given host closes the socket early
utils.isAnEarlyCloseHost = function (hostname) {
  return hostname && hostname.match(".*google(apis)?.com$");
};

// Returns boolean on whether response contains binary data or not
utils.isBinaryContent = function (response) {
  return (!response.headers || !response.headers["content-type"]) ? false : (response.headers["content-type"].match(/^(image|audio|video)\//));
};

// Removes leading and trailing whitespace
utils.trim = function (string) {
  return this.replace(/^\s\s*/, '').replace(/\s\s*$/, '');
};

// Encodes and replaces values that encodeURIComponent doesn't.
// The only ones you can ignore with OAuth are: - _ . ~
// see - http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:encodeURIComponent
utils.encodeData = function (data) {
  if (data === "" || !data) return "";
  return encodeURIComponent(data).
    replace(/\!/g, "%21").
    replace(/\'/g, "%27").
    replace(/\(/g, "%28").
    replace(/\)/g, "%29").
    replace(/\*/g, "%2A");
};

// Decode URI information with regards to encoding process
utils.decodeData = function (data) {
  if (data !== null) data = data.replace(/\+/g, ' ');
  return decodeURIComponent(data);
};

// Scans header string for key-value information and bearer details
// return: Object || false
utils.parseHeader = function (header) {
  if (header.indexOf(',') === -1) return false;
  var params = {}, match;
  header = utils.trim(header);

  header.split(",").forEach(function (v, i) {
    match = v.match(/(\w+)[:=] ?"?(\w+)?"?/);

    if (match[2] === "=")
      params[match[1]] = utils.decodeData(match[3] || "");
    else
      params['bearer'] = utils.decodeData(match[1]);
  });

  return params;
};