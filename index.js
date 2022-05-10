'use strict';

const jose = require('node-jose');
const axios = require('axios');
const qs = require('qs');

const inputDataValidator = require('./validator.js');

const stagUrl = 'https://preprod.signicat.com/oidc/';
const prodUrl = 'https://id.signicat.com/oidc/';
const httpOptions = { timeout: 10000 };

module.exports = function Signicat(config) {
  console.log('Signicat config:', config);
  inputDataValidator.validateConfig(config);
  const apiUrl = config.isProd ? prodUrl : stagUrl;

  async function decryptToken(token) {
    console.log('Signicat/decryptToken() token:', token);

    const privateJwk = await jose.JWK.asKey(config.privateJwk);
    const result = await jose.JWE.createDecrypt(privateJwk).decrypt(token);
    return result.payload.toString();
  }

  async function getPublicKey(use) {
    console.log('Signicat/getPublicKey() use:', use);

    const { data: jwks } = await axios.get(apiUrl + 'jwks.json', httpOptions);

    if (!jwks) {
      throw new Error(`Unable to fetch JWK public keys from ${apiUrl + 'jwks.json'}`);
    }

    const pubKey = jwks.keys.find(elem => elem.use === use && !elem.kid.includes('any.oidc-signature'));

    if (!pubKey || !pubKey.kid || pubKey.kty !== 'RSA') {
      throw new Error(`Invalid JWK ${use} public key from ${apiUrl + 'jwks.json'}`);
    }
    return pubKey;
  }

  async function verifyTokenSignature(token) {
    console.log('Signicat/verifyTokenSignature()');

    const pubKey = await getPublicKey('sig');
    try {
      const sigKey = await jose.JWK.asKey(pubKey);
      console.log('Signicat/verifyTokenSignature() sigKey:', sigKey);
      const verified = await jose.JWS.createVerify(sigKey).verify(token);
      console.log('Signicat/verifyTokenSignature() verified:', verified);
      return JSON.parse(verified.payload.toString());
    } catch (err) {
      console.error('Signicat/verifyTokenSignature() ERROR! Cannot verify signature; err:', err);
      throw err;
    }
  }

  async function getAuthorizationUrl(params) {
    console.log('Signicat/getAuthorizationUrl()');

    inputDataValidator.validateGetAuthorize(params);
    const authorizationUrl = new URL(apiUrl + 'authorize');

    if (config.FTN === true) {
      const jwk = await getPublicKey('enc');
      params.client_id = config.client_id;
      const payloadBuffer = Buffer.from(JSON.stringify(params));
      // Preparing RSA key
      const key = await jose.JWK.asKey(jwk);
      // Encoding JWE token
      // Signicat OIDC server requires "kid" in header of JWE token (node-jose does it automatically)
      const enc = await jose.JWE.createEncrypt({ format: 'compact' }, key).update(payloadBuffer).final();
      authorizationUrl.searchParams.append('request', enc);
    } else {
      authorizationUrl.searchParams.append('client_id', config.client_id);

      for (const [key, value] of Object.entries(params)) {
        if (Array.isArray(value)) {
          value.forEach(elem => {
            authorizationUrl.searchParams.append(key, elem);
          });
        } else {
          authorizationUrl.searchParams.append(key, value);
        }
      }
    }

    console.log('Signicat/getAuthorizationUrl() authorizationUrl:', authorizationUrl);
    return authorizationUrl.href;
  }

  async function postAccessToken(params) {
    console.log('Signicat/postAccessToken() params:', params);
    inputDataValidator.validatePostToken(params);

    const data = config.client_id + ':' + config.secret;
    const buff = new Buffer.from(data);
    const base64data = buff.toString('base64');
    const body = {
      client_id: config.client_id,
      redirect_uri: params.redirect_uri,
      grant_type: params.grant_type,
      code: params.code // Code from getAuthorize
    };
    console.log('Signicat/postAccessToken() body:', body);

    const stringifiedBody = qs.stringify(body);

    const options = { ...httpOptions, headers: { Authorization: 'Basic ' + base64data }};
    const { data: response } = await axios.post(apiUrl + 'token', stringifiedBody, options);

    if (config.FTN === true) {
      const idToken = await decryptToken(response.id_token);
      const idTokenInfo = await verifyTokenSignature(idToken);
      response.nonce = idTokenInfo.nonce;
      console.log('Signicat/postAccessToken() FTN true; add nonce to response; nonce:',idTokenInfo.nonce);
    }

    console.log('Signicat/postAccessToken() response:', response);
    return response;
  }

  /*
    curl -XGET "https://preprod.signicat.com/oidc/userinfo" -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
  */
  async function getUserInfo(params) {
    inputDataValidator.validateGetUserInfo(params);
    const bearer = params.access_token;

    let options = {
      ... httpOptions,
      headers: { Authorization: 'Bearer ' + bearer }
    };

    const { data: response } = await axios.get(apiUrl + 'userinfo', options);

    let userInfo = response;
    if (config.FTN === true) {
      const userInfoToken = await decryptToken(response);
      userInfo = await verifyTokenSignature(userInfoToken);
    }

    return userInfo;
  }

  return {
    getAuthorizationUrl,
    postAccessToken,
    getUserInfo,
    apiUrl,
    getPublicKey,
    verifyTokenSignature,
    decryptToken
  };
};
