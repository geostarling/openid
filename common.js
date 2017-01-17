/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * If applicable, add the following below this MPL 2.0 HEADER, replacing
 * the fields enclosed by brackets "[]" replaced with your own identifying
 * information:
 *     Portions Copyright [yyyy] [name of copyright owner]
 *
 *     Copyright 2013-2014 ForgeRock AS
 *
 */
// START CONFIGURATION...

// To avoid cross-site scripting questions,
// this demo should be in the same container
// as the OpenID Connect provider (OpenAM).
function getBaseURL() {
    var protocol = window.location.protocol;
    var hostname = window.location.hostname;
    var port     = window.location.port;
    return protocol + "//" + hostname + ":" + port;
}
var server        = getBaseURL();

// OpenAM is assumed to be deployed under /openam.
var openam        = "/openam";
var authorize     = "/oauth2/authorize";
var access        = "/oauth2/access_token";
var info          = "/oauth2/userinfo";
var jwks_uri      = "/oauth2/connect/jwk_uri?realm=/fo";


// This application's URI, client_id, client_secret.
var openid        = "/openid";
var client_id     = "sampleclient-openid-4e841c1c-0b4b-4ccc-a47e-fd2a7edb20bf";
var client_secret = "b34666a8853242eeafdbb679f1a1cd83";
//var client_id     = "liferay-lfrdevweb-614c7bb0-7837-4b53-9f63-f6c19aed2c43";
//var client_secret = "e51b17769a384b8bb7127c4aa1c7f87d";

var client_realm  = "/fo";


// ...END CONFIGURATION

// http://stackoverflow.com/ has lots of useful snippets...
function encodeQueryData(data) {
    var ret = [];
    for (var d in data) {
        ret.push(encodeURIComponent(d) + "="
            + encodeURIComponent(data[d]));
    }
    return ret.join("&");
}

/* Returns a map of query string parameters. */
function parseQueryString() {
    var query = {};
    var args  = document.location.search.substring(1).split('&');
    for (var arg in args) {
        var m = args[arg].split('=');
        query[decodeURIComponent(m[0])] = decodeURIComponent(m[1]);
    }

    return query;
}

/* Validates a JWS signature according to
   https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-33#section-5.2
   cheating a bit by taking the pre-encoded header and payload.
 */
function validateSignature(encodedHeader, encodedPayload, signature, alg, key) {
  if (alg === 'RS256') {
    var signKey = KEYUTIL.getKey(key);
    return KJUR.jws.JWS.verifyJWT(encodedHeader + "." + encodedPayload + "." + signature, signKey, {alg: ["RS256"]});
 } else {
    var signingInput   = encodedHeader + "." + encodedPayload;
    var signed         = CryptoJS.HmacSHA256(signingInput, key);
    var encodedSigned  = b64tob64u(signed.toString(CryptoJS.enc.Base64));  
    return encodedSigned == signature;
  }
}

/* Returns a base64url-encoded version of the base64-encoded input string. */
function b64tob64u(string) {
    var result = string;
    result = result.replace(/\+/g, "-");
    result = result.replace(/\//g, "_");
    result = result.replace(/=/g, "");
    return result;
}

function findKeyInJWKS(jwks, kid) {
    for (var i = 0; i < jwks.keys.length; i++) {
        if (jwks.keys[i].kid === kid) {
            return jwks.keys[i];
        }
    }
    return null;
}