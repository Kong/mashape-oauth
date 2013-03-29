# OAuth Flows / Reference

I tried to make this as understandable as possible for any party reading it which means that the wording, references, and terminology used may not reflect that of a technical paper or resource. Excuse me if you may for I wish all to understand this, and not just those with a degree in understanding legal or technical jargon.

## Table Of Contents

1. [Terminology / Reference](#terminology--reference)
   1. [Signed Requests](#signed-requests)
2. OAuth 1.0a
   1. [One Legged](#oauth-10a-one-legged)
   2. [Two Legged](#oauth-10a-two-legged)
   3. [Three Legged](#oauth-10a-three-legged)
   4. [Echo](#oauth-10a-echo)
   5. [xAuth](#oauth-10a-xauth)
3. OAuth2
   1. [Two-Legged](#oauth2-two-legged)

## Terminology / Reference

* Signed / Signature
  - This is usually a joined string of (the base) `Request Method` `&` `URL Query` `&` `Parameters (Sorted & Encoded)` and then encrypted against the key (`consumer_secret` `&` `token_secret`) for the final signature. In some cases this may be the **key**, Plaintext, or may use simply the `consumerSecret`, RSA.
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
  - URL Query String `?query=looks&like=this`
* Parameter / Argument
  - These are snippets of information that have a name reference such as `oauth_token="helloWorld"` where `oauth_token` is the parameter or argument and `helloWorld` is the value.
* Plaintext
  - Signature Encryption Method, Plain Text, as in Human Readable Text such as this is.
* HMAC-SHA1 [[W](http://en.wikipedia.org/wiki/Hash-based_message_authentication_code)]
  - Signature Encryption Method, Secure Hash Algorithm (1) Method, Encrypted Text
* RSA-SHA1 [[W](http://en.wikipedia.org/wiki/RSA_(algorithm\))]
  - Signature Encryption Method, Secure Hash Algorithm (1) coupled with a public and private key. You may have seen this being used for your github account at one point, also in SSH.
* Service
  - Provider of information, data-source, or supplying use. Twitter is an example of a service.
* Signature Method
  - OAuth Accepted Encryption method, one of the following: PLAINTEXT, HMAC-SHA1, and RSA-SHA1.
* Value
  - Information in relation to something such as a parameter.
* URL / URI
  - Location on the internet or resource locator.
  
### Signed Requests

Signing a requests is more than just the signature step, it also includes either the header or query creation step. In this step the Application takes all the information it has gathered and generated and places in a single string.

Some requests will use the `OAuth` header for this, and others will use another which is the URL Query. In this section, we will look at how the signature process should be handled and how each parameter should be used with references to flows.

***

**Note:** This section is in regards to OAuth 1.0

***

On the first leg of generating such a string we must collect all the required parameters and their values, some of these are used inside of the string directly and others in-directly through the encryption or encoding of the signature.

#### Signature Base String

Gathering the `Method` of the request, the `URL` of the request (or in the case of Echo the verifying credentials URL) and the `Query String` joined together by the `&` character would look like this raw (taken from [this](https://dev.twitter.com/docs/auth/creating-signature) twitter page):

```
POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521
```

##### Signing Key

Which is then encoded against a *signing key* which in some flows is different than others but is always a joining of the OAuth `Consumer Secret` and `Token Secret` once again by the `&` character like so:

***

**Note:** Sometimes in case of RSA and xAuth the signing key may only be the `Consumer Secret` with an `&` appended or not. For more insights check out lines [180](https://github.com/Mashape/mashape-oauth/blob/master/lib/oauth.js#L180) & [186](https://github.com/Mashape/mashape-oauth/blob/master/lib/oauth.js#L186) of mashape-oauth/lib/oauth.js

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

The OAuth header is a part of the signed request, it contains the `oauth_signature` and `oauth_signature_method` parameters and their values. It is a single string and seperated generally by a comma (spaces are supported here by some services, stick to comma by default unless told otherwise by the service) and named `Authorization` with `OAuth` being the Bearer, in other flows this may change such as the OAuth Mac Bearer and other similiar methods.

The header itself is built up by all the `oauth_*` parameters sorted (by name, then some more [complex things](https://github.com/Mashape/mashape-oauth/blob/master/lib/oauth.js#L111)). Here is an example taken from Twitter for getting a Request Token:

```
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

The `oauth_callback` is what twitter will invoke or respond to when the authentication step happens, some services tell you they have successfully confirmed this information with a `oauth_callback_confirmed` token (This should be the defacto situation).

Now, lets see the example response:

```
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

Generally, the `oauth_token` will be sent along as a query parameter `?oauth_token=[token goes here]` on the authenticate endpoint if we were doing a three-legged OAuth 1.0a request which should give you back the `oauth_token` and `oauth_verifier` which then are used as well in your  Access Token request [[19]](https://dev.twitter.com/docs/auth/implementing-sign-twitter).

## OAuth 1.0a (one-legged)

What is commonly known as two-legged is actually one legged, there is only one step, thus you are standing on one leg.

***

**Note:** Google requires an unorthodox non-oauth parameter that must be added to the query string of the url you are 
request called `xoauth_requester_id` [[R](https://developers.google.com/google-apps/gmail/oauth_protocol#oauth_request_url)] 
this has also been depricated in favor of OAuth2.

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

The most secure OAuth implementation so far, yet a little more complicated seeing as the user is a part of the handshake and must interact with ui's during the transactions.

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

## OAuth 2 (three-legged)

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