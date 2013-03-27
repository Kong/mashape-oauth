exports.SHA1 = require('./sha1');

exports.extend = function (original, context) {
  var output = JSON.parse(JSON.stringify(original || {})), key;
  for (key in context)
    if (context.hasOwnProperty(key))
      if (Object.prototype.toString.call(context[key]) === '[object Object]')
        output[key] = exports.extend(output[key] || {}, context[key]);
      else
        output[key] = context[key];
  return output;
};

exports.serialExtend = function (original, context, prefix) {
  var output = JSON.parse(JSON.stringify(original || {})), i, key, value;
  for (i in context) {
    if (!context.hasOwnProperty(i)) continue;
    else key = prefix ? prefix + "[" + i + "]" : i, value = context[i];
    if (Object.prototype.toString.call(value) === '[object Object]')
      output = exports.serialExtend(output, value, key);
    else
      output[key] = value;
  }
  return output;
};

exports.isAnEarlyCloseHost = function (hostName) {
  return hostName && hostName.match(".*google(apis)?.com$");
};

exports.isBinaryContent = function (response) {
  return (!response.headers || !response.headers["content-type"]) ? false : (response.headers["content-type"].match(/^(image|audio|video)\//));
};