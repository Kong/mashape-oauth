# OAuth Flows / Reference

I tried to make this as understandable as possible for any party reading it which means that the wording, references, and terminology used may not reflect that of a technical paper or resource. Excuse me if you may for I wish all to understand this, and not just those with a degree in understanding legal or technical jargon.

## Table Of Contents

1. OAuth 1.0a
   1. [One Legged](#oauth-10a-one-legged)
   2. [Two Legged](#oauth-10a-two-legged)
   3. [Three Legged](#oauth-10a-three-legged)
   4. Echo
   5. XAuth
2. OAuth2

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
* Signature Method
  - OAuth Accepted Encryption method, one of the following: PLAINTEXT, HMAC-SHA1, and RSA-SHA1.
* Value
  - Information in relation to something such as a parameter.
* URL / URI
  - Location on the internet or resource locator.

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
2. Server Validates and Grants Access to Resources.
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
3. Exchange Request Token for Access Token (**signed** request)
    - `oauth_token` *Request Token*
    - `oauth_consumer_key`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version`
3. Server grants Access Token & Token Secret (same arguments generally as Step 2)
4. Application uses `oauth_token` & `oauth_token_secret` to access protected resources.

Here is the actual flow of OAuth 1.0a 2-legged, here we can see the extra security measures in place to make sure a secure access connection has been made without bothering the user to authorize details.

## OAuth 1.0a (three-legged)

This flow is the full experience, the grand finale, the whole shebang. It's the full-flow of OAuth 1.0a, and the most complex, excluding the other two variants on it. The user interaction in the middle of the flow is usually what causes most confusion.

***

<img src="http://puu.sh/2ph9x.png" align="right" />

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
3. Exchange Request Token / Verifier for Access Token (**signed** request)
    - `oauth_token` *Request Token;*
    - `oauth_consumer_key`
    - `oauth_nonce`
    - `oauth_signature`
    - `oauth_signature_method`
    - `oauth_version`
    - `oauth_verifier`
3. Server grants Access Token & Token Secret (same arguments generally as Step 2)
4. Application uses `oauth_token` & `oauth_token_secret` to access protected resources.

***

**Note:** In *Step 6* if `oauth_verifier` has not been set, this is a failed OAuth 1.0a 3-Legged implementation and probably only requires the `oauth_token` to be sent. Rarely seen but they exist.

***

The most secure OAuth implementation so far, yet a little more complicated seeing as the user is a part of the handshake and must interact with ui's during the transactions.

## OAuth 2