# Mashape OAuth

OAuth Modules for Node.js - Supporting RSA, HMAC, PLAINTEXT, 2,3-Legged, 1.0a, Echo, XAuth, and 2.0

# Installation

```
npm install mashape-oauth
```

# Usage

Using OAuth (1.x, XAuth, Echo):

```javascript
var OAuth = require('mashape-oauth').OAuth;

var oa = new OAuth({ /* ... options ... */ }, callback);
```

**Argument Documentation**

- options `{Object}` OAuth Request Options
  - echo `{Object}` *Optional;* If it exists we treat the request as an echo request. See [Twitter](https://dev.twitter.com/docs/auth/oauth/oauth-echo).
  - echo.verifyCredentials `{String}` What is the credentials URI to delegate against?
  - realm `{String}` *Optional;* Access Authentication Framework Realm Value, Commonly used in Echo Requests, allowed in all however:
  [Section 3.5.1](http://tools.ietf.org/html/rfc5849#section-3.5.1)
  - requestUrl `{String}` Request Token URL, [Section 6.1](http://oauth.net/core/1.0/#auth_step1)
  - accessUrl `{String}` Access Token URL, [Section 6.2](http://oauth.net/core/1.0/#auth_step2)
  - callback `{String}` URL the Service Provider will use to redirect User back to Consumer after obtaining User Authorization has been completed.
  [Section 6.2.1](http://oauth.net/core/1.0/#auth_step2)
  - consumerKey `{String}` The Consumer Key
  - consumerSecret `{String}` The Consumer Secret
  - version `{String}` *Optional;* By spec this is `1.0` by default. [Section 6.3.1](http://oauth.net/core/1.0/#auth_step3)
  - signatureMethod `{String}` Type of signature to generate, must be one of:
    - PLAINTEXT
    - RSA-SHA1
    - HMAC-SHA1
  - nonceLength `{Number}` *Optional;* Length of nonce string. Default `32`
  - headers `{Object}` *Optional;* Headers to be sent along with request, by default these are already set.
  - clientOptions `{Object}` *Optional;* Contains `requestTokenHttpMethod` and `accessTokenHttpMethod` value.
  - parameterSeperator `{String}` *Optional;* Seperator for OAuth header parameters, default is `,`
- callback `{String}` *Optional;* callback uri, over-rides options callback.

Using OAuth2:

```javascript
var OAuth2 = require('mashape-oauth').OAuth2;

var oa = new OAuth2({ /* ... options ... */ }, callback);
```

**Argument Documentation:**

- options `{Object}` OAuth Request Options
  - clientId `{String}` Client Identifier
  - clientSecret `{String}` Client Secret
  - baseUrl `{String}` Base url of OAuth request
  - authorizationUrl `{String}` *Optional;* Authorization endpoint, default is `/oauth/authorize`
  - authorizationMethod `{String}` *Optional;* Authorization Header Method, default is `Bearer`
  - accessTokenUrl `{String}` *Optional;* Access Token Endpoint, default is `/oauth/access_token`
  - accessTokenName `{String}` *Optional;* Access Token Parameter Name, default is `access_token`
  - headers `{Object}` *Optional;* Custom headers we wish to pass along

