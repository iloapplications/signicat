'use strict';

const stagUrl = 'https://preprod.signicat.com/oidc/';
const prodUrl = 'https://id.signicat.com/oidc/';
const inputDataValidator = require('./validator.js');
const jose = require('node-jose');

module.exports = function Signicat(config) {
  inputDataValidator.validateConfig(config);
  const apiUrl = config.isProd ? prodUrl : stagUrl;

async function decryptToken(token) {
    const privateJwk = await jose.JWK.asKey(config.privateJwk);
    const result = await jose.JWE.createDecrypt(privateJwk).decrypt(token);
    return result.payload.toString();
  }

  async function getPublicKey(use) {
    const rpOptions = {
      method: 'GET',
      json: true,
      uri: apiUrl + 'jwks.json',
    };
    const jwks = await config.requestPromise(rpOptions);
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
    const pubKey = await getPublicKey('sig');
    const sigKey = await jose.JWK.asKey(pubKey);
    const verified = await jose.JWS.createVerify(sigKey).verify(token);
    return JSON.parse(verified.payload.toString());
  }
  /*
    GET /authorize?
      respose_type=code
      &scope=openid profile email
      &client_id=config.clientId
      &state=af=ifjsldkj
      &redirect_uri=https://server.example.com:443/oidcclient/redirect/client01
      &acr_values=urn:signicat:oidc:method:scid-proof
      &login_hint=deviceId-92855960
      &login_hint=authType-email
  */
  async function getAuthorizationUrl(params) {
    inputDataValidator.validateGetAuthorize(params);
    let authorizationUrl = new URL(apiUrl + 'authorize');

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

    return authorizationUrl.href;
  }

  async function postAccessToken(params) {
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
    const rpOptions = {
      method: 'POST',
      json: true,
      uri: apiUrl + 'token',
      form: body,
      headers: {
        'Authorization': 'Basic ' + base64data
      }
    };
    const response = await config.requestPromise(rpOptions);

    if (config.FTN === true) {
      const idToken = await decryptToken(response.id_token);
      const idTokenInfo = await verifyTokenSignature(idToken);
    }

    return response;
  }

  /*
    curl -XGET "https://preprod.signicat.com/oidc/userinfo" -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
  */
  async function getUserInfo(params) {
    inputDataValidator.validateGetUserInfo(params);
    const bearer = params.access_token;
    const rpOptions = {
      method: 'GET',
      json: true,
      uri: apiUrl + 'userinfo',
      headers: {
        'Authorization': 'Bearer ' + bearer
      }
    };

    const response = await config.requestPromise(rpOptions);
    let userInfo = response;
    if (config.FTN === true) {
      const userInfoToken = await decryptToken(response);
      userInfo = await verifyTokenSignature(userInfoToken);
    }

    // Extract SSN (social security number)
    userInfo.ssn = userInfo['signicat.national_id'] ||
      userInfo['signicat.national-id'] ||
      userInfo['tupas.customer.id'] ||
      userInfo['tupas.customer.id.plaintext'] ||
      userInfo['national-id.fi.hetu'] ||
      userInfo['national-identity'];

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
