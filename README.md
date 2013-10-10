# Mashape OAuth

OAuth Modules for Node.js - Supporting RSA, HMAC, PLAINTEXT, 2-Legged, 3-Legged, 1.0a, Echo, XAuth, and 2.0

### OAuth Bible

If you're looking for the popular OAuth Bible, [here it is](https://github.com/Mashape/mashape-oauth/blob/master/FLOWS.md). It extensively explains the multitude of OAuth flows and how OAuth works.

# Installation

```
npm install mashape-oauth
```

# Features

- Handles binary responses
- Handles gzipped responses
- Supports having an empty oauth_token for 1.0a
- Supports Plaintext, HMAC-SHA1, and RSA encryption for 1.0a
- Object based parameter system and supports chaining
- Code has been refactored to be more performant in loops, whiles, and callback structures.
- Intuitive method naming, small footprint, and tested against test suites as well as hundreds of APIs.

# Usage

Require the library and the one you wish to use.

1. [OAuth](#using-oauth-1x-xauth-echo)
  1. [getOAuthRequestToken](#getoauthrequesttoken---creating-request-token-call)
  2. [getOAuthAccessToken](#getoauthaccesstoken---creating-oauth-access-token-call)
  2. [getXAuthAccessToken](#getxauthaccesstoken---creating-xauth-access-token-call)
  3. [Request Methods](#request-methods)
2. [OAuth2](#using-oauth2)

***

### Using OAuth (1.x, XAuth, Echo):

```javascript
var OAuth = require('mashape-oauth').OAuth;
var oa = new OAuth({ /* … options … */ }, callback);
```
- `options` `Object` *OAuth request options*
  - `echo` `Object` ___Optional___ *If it exists we treat the request as OAuth Echo request. See [Twitter](https://dev.twitter.com/docs/auth/oauth/oauth-echo)*
      - `verifyCredentials` `String` *What is the credentials URI to delegate against?*
  - `realm` `String` ___Optional___ *Access Authentication Framework Realm Value, Commonly used in Echo Requests, allowed in all however: [Section 3.5.1](http://tools.ietf.org/html/rfc5849#section-3.5.1)*
  - `requestUrl` `String` *Request Token URL. [Section 6.1](http://oauth.net/core/1.0/#auth_step1)*
  - `accessUrl` `String` *Access Token URL. [Section 6.2](http://oauth.net/core/1.0/#auth_step2)*
  - `callback` `String` *URL the Service Provider will use to redirect User back to Consumer after obtaining User Authorization has been completed. [Section 6.2.1](http://oauth.net/core/1.0/#auth_step2)*
  - `consumerKey` `String` *The Consumer Key*
  - `consumerSecret` `String` *The Consumer Secret*
  - `version` `String` ___Optional___ *By spec this is `1.0` by default. [Section 6.3.1](http://oauth.net/core/1.0/#auth_step3)*
  - `signatureMethod` `String` *Type of signature to generate, must be one of:*
      - `PLAINTEXT`
      - `RSA-SHA1`
      - `HMAC-SHA1`
  - `nonceLength` `Number` ___Optional___ *Length of nonce string. Default `32`*
  - `headers` `Object` ___Optional___ *Headers to be sent along with request, by default these are already set.*
  - `clientOptions` `Object` ___Optional___ *Contains `requestTokenHttpMethod` and `accessTokenHttpMethod` value.*
  - `parameterSeperator` `String` ___Optional___ *Seperator for OAuth header parameters. Default is `,`*

#### getOAuthRequestToken() - Creating Request Token Call

```javascript
oa.getOAuthRequestToken({ /* … parameters … */ }, callback);
```

- `parameters` `Object` ___Optional___ *Additional Headers you might want to pass along.*
  - *If omitted, you can treat parameters argument as callback and pass along a function as a single parameter.*
- `callback` `Function` *Anonymous Function to be invoked upon response or failure.*


##### Example

```javascript
oa.getOAuthRequestToken(function (error, oauth_token, oauth_token_secret, results) {
  if (error)
    return res.send('Error getting OAuth Request Token: ' + error, 500);
  else
    // Usually a redirect happens here to the /oauth/authorize stage
    return res.send('Successfully Obtained Token & Secret: ' + oauth_token + ' & ' + oauth_token_secret, 200);
});
```

#### getOAuthAccessToken() - Creating OAuth Access Token Call

```javascript
oa.getOAuthAccessToken(options, callback);
```

- `options` `Object`
  - `oauth_verifier` `String` *Verification code tied to the Request Token. [Section 2.3](http://tools.ietf.org/html/rfc5849#section-2.3)*
  - `oauth_token` `String` *Request Token*
  - `oauth_token_secret` `String` *Request Token Secret, used to help generation of signatures.*
  - `parameters` `Object` ___Optional___ *Additional headers to be sent along with request.*
  - `callback` `Function` ___Optional___ *Method to be invoked upon result, over-ridden by argument if set.*
- `callback` `Function` *Anonymous Function to be invoked upon response or failure, setting this overrides previously set callback inside options object.*


##### Example

```javascript
oa.getOAuthAccessToken({
  oauth_verifier: 'ssid39b',
  oauth_token: 'request_key',
  oauth_secret: 'request_secret'
}, function (error, token, secret, result) {
  if (error)
    return res.send('Error getting XAuth Access Token: ' + error, 500);
  else
    // Usually you want to store the token and secret in a session and make your requests after this
    return res.send('Successfully Obtained Token & Secret: ' + oauth_token + ' & ' + oauth_token_secret, 200);
});
```

#### getXAuthAccessToken() - Creating XAuth Access Token Call

```javascript
oa.getXAuthAccessToken(username, password, callback);
```

- `username` `String` XAuth Username credentials of User obtaining a token on behalf of
- `password` `String` XAuth Password credentials of User obtaining a token on behalf of
- `callback` `Function` Anonymous Function to be invoked upon response or failure.


##### Example

```javascript
oa.getXAuthAccessToken('nijikokun', 'abc123', function (error, oauth_token, oauth_token_secret, results) {
  if (error)
    return res.send('Error getting XAuth Access Token: ' + error, 500);
  else
    // Usually you want to store the token and secret in a session and make your requests after this
    return res.send('Successfully Obtained Token & Secret: ' + oauth_token + ' & ' + oauth_token_secret, 200);
});
```

#### Request Methods

```javascript
oa.post(options, callback);
oa.get(options, callback);
oa.delete(options, callback);
oa.patch(options, callback);
oa.put(options, callback);

// Alternatively, you can use the old node-oauth style: (Where method is one of five above.)
oa.method(url, oauth_token, oauth_token_secret, body, type, parameters, callback);
```

- `options` `Object` Contains Request Information
  - `url` `String` URL to be requested upon
  - `oauth_token` `String` *Optional;* Dependant upon request step, could be access, or request token.
  - `oauth_token_secret` `String` *Optional;* Dependant upon request step
  - `body` `String` *Optional;* Body information to be sent along with request.
  - `type` `String` *Optional;* Content Request Type
  - `parameters` `Object` *Optional;* Additional headers you wish to pass along with your request.
  - `callback` `Function` *Optional;* Method to be invoked upon result, over-ridden by argument if set.
- `callback` `Function` Method to be invoked upon result, over-rides options callback.

***

### Using OAuth2:

```javascript
var OAuth2 = require('mashape-oauth').OAuth2;
var oa = new OAuth2({ /* … options … */ }, callback);
```

- `options` `Object` OAuth Request Options
  - `clientId` `String` Client Identifier
  - `clientSecret` `String` Client Secret
  - `baseUrl` `String` Base url of OAuth request
  - `authorizationUrl` `String` *Optional;* Authorization endpoint, default is `/oauth/authorize`
  - `authorizationMethod` `String` *Optional;* Authorization Header Method, default is `Bearer`
  - `accessTokenUrl` `String` *Optional;* Access Token Endpoint, default is `/oauth/access_token`
  - `accessTokenName` `String` *Optional;* Access Token Parameter Name, default is `access_token`
  - `headers` `Object` *Optional;* Custom headers we wish to pass along

***
