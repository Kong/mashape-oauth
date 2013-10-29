# The OAuth Bible

I tried to make this as understandable as possible for any party reading it which means that the wording, references, and terminology used may not reflect that of a technical paper or resource. Excuse me if you may for I wish all to understand this, and not just those with a degree in understanding legal or technical jargon.

Created with love by http://mashape.com


## Table Of Contents

1. Reference
   1. [Terminology](#terminology--reference)
   2. [Signed Requests](#signed-requests)
2. OAuth 1.0a
   1. [One Legged](#oauth-10a-one-legged)
   2. [Two Legged](#oauth-10a-two-legged)
   3. [Three Legged](#oauth-10a-three-legged)
   4. [Echo](#oauth-10a-echo)
   5. [xAuth](#oauth-10a-xauth)
3. OAuth2
   1. [Two-Legged](#oauth-2-two-legged)
   2. [Three-Legged](#oauth-2-three-legged)
   3. [Refresh Token](#oauth-2-refresh-token)
4. [Sources](#sources)

## Terminology / Reference

* Signed / Signature
  - String made up of several HTTP request elements in a single string.

  These include the `Request Method` `&` `URL Query` `&` `Parameters`, which is then encrypted against the key which consists of: (`consumer_secret` `&` `token_secret`). In some cases this may be the key, plaintext, or may use simply the `consumer_secret`, for RSA encryption.
* Consumer Secret
  - Usually given by application as a secret token for starting the OAuth handshakes.
* Consumer Key
  - Key usually given along-side Consumer Secret for OAuth handshakes.
* Nonce / UID
  - Uniquely generated ID of a given length using the `a-zA-Z0-9` charset, by default these are usually `32` characters long.
* OAuth Token
  - This is a token sent by the server or endpoint. It can refer to either the Request or Access token.
* OAuth Token Secret
  - This is a secret generally sent with the response for a certain token. Used for exchanges / refreshing.
* Query
  - Part of the URL that contains key-value data invoked by the `?` symbol, the keys and values are seperated by the `=` sign and each data-store is seperated by the `&` symbol: `?query=looks&like=this`
* Parameter / Argument
  - These are snippets of information that have a name reference such as `oauth_token="helloWorld"` where `oauth_token` is the parameter or argument and `helloWorld` is the value.
* Plaintext
  - Signature Encryption Method, Plain Text, as in Human Readable Text such as this is.
* HMAC-SHA1 [[W](http://en.wikipedia.org/wiki/Hash-based_message_authentication_code)]
  - Signature Encryption Method, Secure Hash Algorithm (1) Method, Encrypted Text
* RSA-SHA1 [[W](http://en.wikipedia.org/wiki/RSA_(algorithm\))]
  - Signature Encryption Method, Secure Hash Algorithm (1) coupled with a public and private key. You may have seen this being used for your Github account at one point, also in SSH.
* Service
  - Provider of information, data-source, or supplying use. Twitter is an example of a service.
* Signature Method
  - OAuth Accepted Encryption method, one of the following: PLAINTEXT, HMAC-SHA1, and RSA-SHA1.
* Value
  - Information in relation to something such as a parameter.
* URL / URI
  - Location on the internet or resource locator.
  
### Signed Requests

> This section is in regards to OAuth 1.0

Signing requests is more than just the signature so in this section we will look at how the signature process should be handled and how each parameter should be used with references to flows. When signing requests the Application takes all the information it has been given, gathered, or generated, and places it in a single location. There are two ways of transporting this information, through the `OAuth` header or the `Query` string.

Before we can generate this string we must gather all the required parameters and their values, some of these are used inside of the string directly and others in-directly through the encryption or encoding of the signature.

#### Signature Base String

Gathering the `Method` of the request, the `URL` of the request (or in the case of `OAuth Echo` the verifying credentials uri) and the `Query String` joined together by the `&` symbol would look like this without encryption (example from [twitter](https://dev.twitter.com/docs/auth/creating-signature)):

```
POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521
```

##### Signing Key

The `signature base` string is then encrypted with a salt called the *signing key* which is a joining of the OAuth `Consumer Secret` and `Token Secret` once again by the `&` character like so:

***

**Note:** Sometimes in case of RSA and xAuth the signing key may only be the `Consumer Secret` with an `&` symbol appended or not. For more insights check out lines [233](https://github.com/Mashape/mashape-oauth/blob/master/lib/oauth.js#L233) & [238](https://github.com/Mashape/mashape-oauth/blob/master/lib/oauth.js#L238) of mashape-oauth/lib/oauth.js

***

```
kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE
```

#### Encoding the Signature

At last, we are able to encode our signature using these two strings of information. If you read the Terminology guide you would know that there are three ways we can do this. PLAINTEXT, HMAC, or RSA. Each method is slightly different from each other.

##### PLAINTEXT

Here we ignore any encoding and simply pass along the `Signature Key`


##### HMAC-SHA1

This encoding method outputs our key into binary which we update our base with, which after this step gets Base64 encoded into it's final signature string:

```
tnnArxj06cWHq44gCs1OSKk/jLY=
```

##### RSA-SHA1

On the more complex side of encoding and security we have the RSA method that we have to encode the generated `private key` against our `Signature Base`.

***

**Note:** Line [74](https://github.com/Mashape/mashape-oauth/blob/master/tests/oauth.js#L74) of mashape-oauth/tests/oauth.js may clear up how to use the generated private key to encode against the signature base.

***

Then on the service side they verify the public key that was generated along-side the private key against the encoded string passed as `oauth_signature`.

#### OAuth Header

The OAuth header is a part of the signed request, it contains the `oauth_signature` and `oauth_signature_method` parameters and their values. It is a single string and separated generally by a comma (spaces are supported here by some services, stick to comma by default unless told otherwise by the service) and named `Authorization` with `OAuth` being the Bearer, in other flows this may change such as the OAuth Mac Bearer and other similar methods.

The header itself is built up by all the `oauth_*` parameters sorted (by name, then some more [complex things](https://github.com/Mashape/mashape-oauth/blob/master/lib/oauth.js#L111)). Here is an example taken from Twitter for getting a Request Token:

```http
POST /oauth/request_token HTTP/1.1
User-Agent: themattharris' HTTP Client
Host: api.twitter.com
Accept: */*
Authorization:
        OAuth oauth_callback="http%3A%2F%2Flocalhost%2Fsign-in-with-twitter%2F",
              oauth_consumer_key="cChZNFj6T5R0TigYB9yd1w",
              oauth_nonce="ea9ec8429b68d6b77cd5600adbbb0456",
              oauth_signature="F1Li3tvehgcraF8DMJ7OyxO4w9Y%3D",
              oauth_signature_method="HMAC-SHA1",
              oauth_timestamp="1318467427",
              oauth_version="1.0"
```

The `oauth_callback` is what twitter will invoke or respond to when the authentication step happens, some services tell you they have successfully confirmed this information with a `oauth_callback_confirmed` token (This should be the de facto situation).

Now, lets see the example response:

```http
HTTP/1.1 200 OK
Date: Thu, 13 Oct 2011 00:57:06 GMT
Status: 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 146
Pragma: no-cache
Expires: Tue, 31 Mar 1981 05:00:00 GMT
Cache-Control: no-cache, no-store, must-revalidate, pre-check=0, post-check=0
Vary: Accept-Encoding
Server: tfe

oauth_token=NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0&
oauth_token_secret=veNRnAWe6inFuo8o2u8SLLZLjolYDmDP7SzL0YfYI&
oauth_callback_confirmed=true
```

Great, `200` response with the `oauth_token`, `oauth_token_secret` and `oauth_callback_confirmed` parameters. This is perfect, now you can use the `oauth_token_secret` for creating your signature for the access token and `oauth_token` for authenticating the request.

Generally, the `oauth_token` will be sent along as a query parameter `?oauth_token=[token goes here]` on the authenticate endpoint when doing a `3-Legged OAuth 1.0a` request which should give you back the `oauth_token` and `oauth_verifier` which then are used as well in your  Access Token request [[19]](https://dev.twitter.com/docs/auth/implementing-sign-twitter).

## OAuth 1.0a (one-legged)

What is commonly known as two-legged is actually one legged, there is only one step, thus you are standing on one leg.

***

**Note:** Google requires an unorthodox non-oauth parameter that must be added to the query string of the url you are 
request called `xoauth_requester_id` [[R](https://developers.google.com/google-apps/gmail/oauth_protocol#oauth_request_url)] 
this has also been deprecated in favor of OAuth2.

***

<img src="http://puu.sh/2pe07.png" align="right" />

1. Application sends a **signed** request to the Service giving it:
    - `oauth_token` *Empty String*
    - `oauth_consumer_key`
    - `oauth_timestamp`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version` *Optional*
2. Service Validates and Grants Access to Resources.
3. Application Utilizes Requested Resources

This is probably the most quickest method of consuming an OAuth implementation however it comes with a few drawbacks on security which you can assume for yourself whether it is the best for your application.

## OAuth 1.0a (two-legged)

The real two-legged OAuth implementation, so lucrative it's like finding a diamond in the rough. Here we also avoid the user authentication step but follow the other flows of OAuth.

***

<img src="http://puu.sh/2peUI.png" align="right" />

1. Application sends a **signed** request for a Request Token:
    - `oauth_consumer_key`
    - `oauth_timestamp`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version` *Optional*
2. Grants application Request Token:
    - `oauth_token`
    - `oauth_token_secret`
    - … Additional Parameters / Arguments
3. Exchange Request Token for Access Token, **signed** request
    - `oauth_token` *Request Token*
    - `oauth_consumer_key`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version`
3. Service grants Access Token & Token Secret (same arguments generally as Step 2)
4. Application uses `oauth_token` & `oauth_token_secret` to access protected resources.

Here is the actual flow of OAuth 1.0a 2-legged, here we can see the extra security measures in place to make sure a secure access connection has been made without bothering the user to authorize details.

## OAuth 1.0a (three-legged)

This flow is the full experience, the grand finale, the whole shebang. It's the full-flow of OAuth 1.0a, and the most complex, excluding the other two variants on it. The user interaction in the middle of the flow is usually what causes most confusion.

***

<img src="http://puu.sh/2pJ4y" align="right" />

1. Application sends a **signed** request for a Request Token:
    - `oauth_consumer_key`
    - `oauth_timestamp`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version` *Optional*
    - `oauth_callback`
2. Grants application Request Token:
    - `oauth_token`
    - `oauth_token_secret`
    - `oauth_callback_confirmed`
    - … Additional Parameters / Arguments
3. Send user to authorize url using:
    - `oauth_token`
4. Prompts user to authorize / grant access
5. User grants access
6. Directs back to application with:
    - `oauth_token`
    - `oauth_verifier`
3. Exchange Request Token / Verifier for Access Token, **signed** request
    - `oauth_token` *Request Token;*
    - `oauth_consumer_key`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version`
    - `oauth_verifier`
3. Service grants Access Token & Token Secret (same arguments generally as Step 2)
4. Application uses `oauth_token` & `oauth_token_secret` to access protected resources.

***

**Note:** In *Step 6* if `oauth_verifier` has not been set, this is a failed OAuth 1.0a 3-Legged implementation and probably only requires the `oauth_token` to be sent. Rarely seen but they exist.

***

The most secure OAuth implementation so far, yet a little more complicated seeing as the user is a part of the handshake and must interact with interfaces during the transactions.

## OAuth 1.0a (Echo)

Not necessarily the most common of OAuth implementations, but it exists. Created by Raffi from twitter it uses two extra headers in the initial request token step to validate your user on their behalf by delegation.

So essentially the Service (third-party, delegator) will authenticate and verify the user against the originating service such as Twitter (Origin Service).

***

<img src="http://puu.sh/2pKKr.png" align="right" />


1. Application sends a signed request along with any data and:
    - `oauth_consumer_key`
    - `oauth_timestamp`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version` *Optional*
    - `oauth_callback`
    
    Along with two additional headers:
    - `X-Auth-Service-Provider`
    - `X-Verify-Credentials-Authorization`
2. Service takes the additional headers and validates against the Origin Service.
3. Service then validates against given information and returns protected resource information. This could be storing an image, generating the url and returning that information.

## OAuth 1.0a (xAuth)

xAuth is a way for desktop and mobile apps to get an OAuth access token from a user’s email and password, and it is still OAuth. So the third-party will ask for your credentials on the origin service to authenticate with.

The xAuth process will give back read-only, or read-write access tokens. Some limitations can apply, as in the Twitter spec Direct Messages read access is not provided and you must use the full OAuth flow (three-legged).

***

**Note:** The user's credentials should never be kept by the application requesting them.

***

[<img src="http://puu.sh/2qneC.png" align="right" />](http://puu.sh/2qnhm.png)

1. Application Requests User Credentials
2. Application creates signed request for Access Token:
    - `oauth_consumer_key`
    - `oauth_timestamp`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version` *Optional*
    - `oauth_callback`
    
    Along with additional parameters:
    - `x_auth_mode` = `client_auth`
    - `x_auth_username`
    - `x_auth_password`
    - `x_auth_permission` *Optional;* Scope of the requested token [[17]](http://developer.vimeo.com/apis/advanced)
2. Service validates user details and grants Access Token
    - `oauth_token`
    - `oauth_token_secret`
3. Application uses Access Token to retrieve protected resources.


## OAuth 2 (two-legged)

By far the easiest to explain, here we have what is called a *Client Credentials* authorization flow. [[20, 4.4]](http://tools.ietf.org/html/rfc6749#section-4.4) Which is also basically just the *Resource Owner Password* flow without the username and password appended to the encoded query passed along as the body, unless the service states through the url in which case is wrong.


***

**Note** If you are using basic, you will need to additionally pass along an `Authorization` header with the bearer type as `Basic` and as the value you use `client_id` `:` `client_secret` Base64 encoded.

```
Authorization: Basic Base64(client_id:client_secret)
```

***

### Client Credentials

1. Application makes request to Service:
  - `grant_type` = `client_credentials`
  
  If you aren't using the `Authorization` header:
  - `client_id`
  - `client_secret`
2. Service responds with Access Token:
    - `access_token`
    - `expires_in`
    - `token_type`

### Resource Owner Password

Basically OAuth 1.0a Echo… without the signing and complications. Let's do this.

1. Application request credentials, *shown below*, from resource owner (also known as the user).
    - `username`
    - `password`
2. Application makes request to Service using the given credentials as a query string for the body:
    - `grant_type` = `password`
    - `username`
    - `password`
    
    It should look like this:
    ```
grant_type=password&username=my_username&password=my_password
```
    
    If you aren't using the `Authorization` header, these must be passed as well:
    - `client_id`
    - `client_secret`
    
    Which would become:
    ```
grant_type=password&username=my_username&password=my_password&client_id=random_string&client_secret=random_secret
```
3. Service responds with Access Token details and expiration information:
    - `access_token`
    - `expires_in`
    - `token_type`


## OAuth 2 (three-legged)

OAuth2 three-legged cuts out a lot of clutter just like the two-legged, no longer are things so complex with signing your requests.

***

**Fun Fact:** Scope by spec was to be space seperated (i.e. `user pull-request`) to which nobody followed and we are now left in a state of constant wonder as to what the next api we tackle uses.

***

1. Application redirects User to Service for Authorization:
    - `client_id`
    - `redirect_uri`
    - `response_type` [[20, 4.1.1]](http://tools.ietf.org/html/rfc6749#section-4.1.1)
    - `state` *Optional;* Unique identifier to protect against CSRF [[25]](http://blog.springsource.org/2011/11/30/10317/)
    - `scope` *Optional;* what data your application can access.
    
    Example Authorization URL (Not-Encoded for Readability):
    
    ```
https://oauth_service/login/oauth/authorize?client_id=3MVG9lKcPoNINVB&redirect_uri=http://localhost/oauth/code_callback&scope=user
    ```
2. User logs into the Service and grants Application access.
3. Service redirects User back to the `redirect_url` with:
    - `code`
    - `state`
4. Application takes the `code` and exchanges it for an Access Token:
    - `client_id`
    - `client_secret`
    - `code`
    - `redirect_uri` *Optional;* see [[20, 4.1.3]](http://tools.ietf.org/html/rfc6749#section-4.1.3)
    - `grant_type` = `"authorization_code"` [[20, 4.1.3]](http://tools.ietf.org/html/rfc6749#section-4.1.3)
2. If `client_id` and `client_secret` are valid the Service will invoke a callback on `redirect_url` that contains an `access_token`:
    - `access_token`
    - `expires_in`
    - `refresh_token`
3. Application stores `access_token` to use in subsequent requests in various manners dependent on the Service.
    - Generally this value is stored in a session or cookie, and then placed into the request as an `Authorization: [Bearer] access_token` header string where `[Bearer]` is the Header Authorization Bearer Name it could be Bearer, OAuth, MAC, etc…


## OAuth 2 (refresh token)

In OAuth2 the `access_token` sometimes, which is most of the time, has a limited lifetime expectancy. We can assume by the `expires_in` parameter passed along at the Access Token response stage whether it will live forever or decay in a certain amount of time.

If an expired token is used the Service will respond with a Session expired or Invalid response error. This means we must use the `refresh_token` along with a few other previously obtained parameters to generate a new one. A lot easier than the whole flow.

***

1. Create request to Service Refresh Token URI:
   - `grant_type` = `"refresh_token"`
   - `scope` *Optional;* Cannot have any new scopes not previously defined.
   - `refresh_token`
   - `client_id`
   - `client_secret`
2. Service validates and responds with the following parameters:
   - `access_token`
   - `issued_at`

## Tips & Tricks

### Generating Access Token & Refresh Key

Instead of encrypting information and using this as a sort of reversible string it's a lot more secure to simply utilize the same method of generation as the `nonce` string, a uuid. Randomly selected characters in a specific length.

#### Example

```javascript
var OAuth = require('mashape-oauth').OAuth,
    access_token = OAuth.nonce(/* Length, Default 32 */);
```

## Sources

Here is a long, windy list of places where I tracked down specific information regarding certain legs or auth specification excluding the original RFC and it's revisions.

1. [Authorizing with OAuth](http://www.flickr.com/services/api/auth.oauth.html) - Flickr Documentation
2. [OAuth on Bitbucket](https://confluence.atlassian.com/display/BITBUCKET/OAuth+on+Bitbucket) - Bitbucket Documentation
3. [OAuth Documentation](https://dev.twitter.com/docs/auth/oauth) - Twitter Documentation
4. [OAuth Extended Flows](http://2.bp.blogspot.com/-Va1Rp3-r898/TZiVh9xEJDI/AAAAAAAAAMw/8ImBIW_dXuY/s1600/OAuth-legs.png)
5. [2-Legged OAuth](https://code.google.com/p/oauth-php/wiki/ConsumerHowTo#Two-legged_OAuth) - OAuth-PHP
6. [OAuth for Consumer Requests](http://oauth.googlecode.com/svn/spec/ext/consumer_request/1.0/drafts/2/spec.html)
7. [OAuth Example](http://term.ie/oauth/example/) - term.ie
8. [OAuth 1.0 Guide](http://hueniverse.com/oauth/guide/) - Heuniverse
9. [OAuth 1.0a Diagram](http://oauth.net/core/diagram.png)
10. [OAuth Wiki](http://wiki.oauth.net)
11. [2-Legged OAuth 1.0 & 2.0](http://architects.dzone.com/articles/2-legged-oauth-oauth-10-and-20) - DZone
12. [OAuth](https://developers.google.com/accounts/docs/OAuth) & [OAuth2](https://developers.google.com/accounts/docs/OAuth2) - Google Documentation
13. [What is 2-legged OAuth?](http://blog.nerdbank.net/2011/06/what-is-2-legged-oauth.html) - Nerdbank
14. [List of Service Providers](http://en.wikipedia.org/wiki/OAuth#List_of_OAuth_service_providers) - Wikipedia
15. [OAuth Echo](http://developers.mobypicture.com/documentation/authentication/oauth-echo/) - mobypicture
16. [OAuth Echo](https://dev.twitter.com/docs/auth/oauth/oauth-echo) - Twitter
17. [Advanced API](http://developer.vimeo.com/apis/advanced) - Vimeo Developer();
18. [About xAuth](https://dev.twitter.com/docs/oauth/xauth) - Twitter xAuth Documentation
19. [Implementing Sign-in](https://dev.twitter.com/docs/auth/implementing-sign-twitter) - Twitter Sign-in Documentation
20. [RFC6749](http://tools.ietf.org/html/rfc6749) - IETF
21. [Web Application Flow](http://developer.github.com/v3/oauth/) - Github OAuth2
22. [OAuth2 Quickstart](http://www.salesforce.com/us/developer/docs/api_rest/Content/quickstart_oauth.htm) - Salesforce
23. [Authentication Mechanisms](https://developers.geoloqi.com/api/authentication) - Geoloqi
24. [Understanding Web Server OAuth Flow](http://www.salesforce.com/us/developer/docs/api_rest/Content/intro_understanding_web_server_oauth_flow.htm) - Salesforce
25. [CSRF & OAuth2](http://blog.springsource.org/2011/11/30/10317/) - Springsource
26. [OAuth v2-31](https://tools.ietf.org/html/draft-ietf-oauth-v2-31) - IETF
27. [Resource Owner Flow](http://techblog.hybris.com/2012/06/11/oauth2-resource-owner-password-flow/) - Hybris
