# OAuth Flows / Reference

I tried to make this as understandable as possible for any party reading it which means that the wording, references, and terminology used may not reflect that of a technical paper or resource. Excuse me if you may for I wish all to understand this, and not just those with a degree in understanding legal or technical jargon.

## Terminology / Reference

* Signed / Signature
  - This is usually a concatination of (the base) `Request Method` `&` `URL Query` `&` `Parameters (Sorted & Encoded)` and then encrypted against the key (`consumerSecret` `&` `token_secret`) for the final signature. In some cases this may be the **key**, Plaintext, or may use simply the `consumerSecret`, RSA.
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
* Parameter / Argument
  - These are snippets of information that have a name reference such as `oauth_token="helloWorld"` where `oauth_token` is the parameter or argument and `helloWorld` is the value.
* Plaintext
  - Signature Encryption Method, Plain Text, as in Human Readable Text such as this is.
* HMAC-SHA1 [[W](http://en.wikipedia.org/wiki/Hash-based_message_authentication_code)]
  - Signature Encryption Method, Secure Hash Algorithm (1) Method, Encrypted Text
* RSA-SHA1 [[W](http://en.wikipedia.org/wiki/RSA_(algorithm\))]
  - Signature Encryption Method, Secure Hash Algorithm (1) coupled with a public and private key. You may have seen this being used for your github account at one point, also in SSH.
* Value
  - Information in relation to something such as a parameter.

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
    - `oauth_consumer_secret`
    - `oauth_consumer_key`
    - `oauth_timestamp`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version` *Optional*
2. Server Validates and Grants Access to Resources.
3. Application Utilizes Requested Resources

This is probably the most quickest method of consuming an OAuth implementation however it comes with a few drawbacks on security which you can assume for yourself whether it is the best for your application.

## OAuth 1.0a (two-legged)

## OAuth 1.0a (three-legged)

## OAuth 2