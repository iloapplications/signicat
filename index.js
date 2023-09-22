'use strict';

const jose = require('node-jose');
const axios = require('axios');
const qs = require('qs');

const inputDataValidator = require('./validator.js');

const httpOptions = { timeout: 15000 };

module.exports = function Signicat(config) {
  console.log('Signicat.config:', config);
  inputDataValidator.validateConfig(config);
  const apiUrl = config.issuerUrl;

  async function decryptToken(token) {
    console.log('Signicat/decryptToken()');

    const privateJwk = await jose.JWK.asKey(config.privateJwk);
    console.log('Signicat/decryptToken() privateJwk:', privateJwk);

    const result = await jose.JWE.createDecrypt(privateJwk).decrypt(token);
    console.log('Signicat/decryptToken() result:', result);

    return result.payload.toString();
  }

  async function getPublicKey(use, pubKidIdentifier = '.') {
    console.log('Signicat/getPublicKey() use:', use);
    console.log('Signicat/getPublicKey() pubKidIdentifier:', pubKidIdentifier);

    const postUrl = '.well-known/openid-configuration/jwks';
    const { data: jwks } = await axios.get(apiUrl + postUrl, httpOptions);

    if (!jwks) {
      throw new Error(`Unable to fetch JWK public keys from ${apiUrl + postUrl}`);
    }
    console.log('Signicat/getPublicKey() jwks:', jwks);

    // const pubKey = jwks.keys.find(elem => elem.use === use && !elem.kid.includes('any.oidc-signature'));
    const pubKey = jwks.keys.find(elem => (elem.use === use) && elem.kid.includes(pubKidIdentifier) && !elem.kid.includes('any.oidc-signature'));
    console.log('Signicat/getPublicKey() pubKey:', pubKey);

    if (!pubKey || !pubKey.kid || pubKey.kty !== 'RSA') {
      throw new Error(`Invalid JWK ${use} public key from ${apiUrl + postUrl}`);
    }
    return pubKey;
  }

  async function verifyTokenSignature(token) {
    console.log('Signicat/verifyTokenSignature()');

    const pubKey = await getPublicKey('sig', config.publicSigIdentifier);
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
    const authorizationUrl = new URL(apiUrl + 'connect/authorize');

    if (config.useJwe === true) {
      const jwk = await getPublicKey('enc', config.publicEncIdentifier);
      params.client_id = config.client_id;
      const payloadBuffer = Buffer.from(JSON.stringify(params));
      // Preparing RSA key
      const key = await jose.JWK.asKey(jwk);
      // Encoding JWE token
      // Signicat OIDC server requires 'kid' in header of JWE token (node-jose does it automatically)
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
    const { data: response } = await axios.post(apiUrl + 'connect/token', stringifiedBody, options);
    console.log('Signicat/postAccessToken() response:', response);

    // let idToken = response.id_token;
    // if (config.FTN === true) {
    //   idToken = await decryptToken(idToken);
    //   console.log('Signicat/postAccessToken() FTN/idToken:', idToken);
    // }
    // if (config.useSig === true) {
    //   idToken = await verifyTokenSignature(idToken);
    //   response.nonce = idToken.nonce;
    //   console.log('Signicat/postAccessToken() useSig/idToken:', idToken);
    //   console.log('Signicat/postAccessToken() FTN true; add nonce to response; nonce:', idToken.nonce);
    // }

    // console.log('Signicat/postAccessToken() response:', response);
    return response;
  }

  /*
    curl -XGET 'https://preprod.signicat.com/oidc/userinfo' -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
  */
  async function getUserInfo(params) {
    console.log('Signicat/getUserInfo() params:', params);
    inputDataValidator.validateGetUserInfo(params);

    const bearer = params.access_token;
    const options = {
      ...httpOptions,
      headers: { Authorization: 'Bearer ' + bearer }
    };

    const { data: response } = await axios.get(apiUrl + 'connect/userinfo', options);

    let userInfo = response;
    console.log('Signicat/getUserInfo() userInfo:', userInfo);

    if (config.FTN === true) {
      userInfo = await decryptToken(response);
      console.log('Signicat/getUserInfo() FTN/userInfo:', userInfo);
    }
    if (config.useSig === true) {
      userInfo = await verifyTokenSignature(userInfo);
      console.log('Signicat/getUserInfo() useSig/userInfo:', userInfo);
    }

    return userInfo;
  }

  //
  // SIGNICAT API FUNCTIONS
  // Authentication API - Redirect flow
  // https://developer.signicat.com/docs/authentication/authentication-api.html#available-flows
  //

  const SIGNICAT_API_ISSUER_ENDPOINT = 'https://api.signicat.com/auth/open/';
  const SIGNICAT_API_ENDPOINT = 'https://api.signicat.com/auth/rest/';

  async function obtainAccessToken(params) {
    console.log('Signicat/obtainAccessToken() params:', params);
    // inputDataValidator.validateObtainAccessToken(params);

    // create authentication header
    const clientId = config.client_id;
    const clientSecret = config.secret;

    // The format is the Base64-encoded string: client_id:client_secret.
    const data = clientId + ':' + clientSecret;
    const buff = Buffer.from(data); // new Buffer?
    const base64data = buff.toString('base64');

    const authHeader = 'Basic ' + base64data;
    console.log('Signicat/obtainAccessToken() authHeader:', authHeader);

    const body = {
      grant_type: 'client_credentials',
      code: 'signicat-api'
    };
    console.log('Signicat/obtainAccessToken() body:', body);
    const stringifiedBody = qs.stringify(body);

    const options = {
      ...httpOptions,
      headers: { Authorization: authHeader }
    };
    console.log('Signicat/obtainAccessToken() options:', options);

    // do request
    const { data: response } = await axios.post(SIGNICAT_API_ISSUER_ENDPOINT + 'connect/token', stringifiedBody, options);
    console.log('Signicat/postAccessToken() response:', response);

    const accessToken = response.access_token;
    return accessToken;
  }

  async function createSession(params) {
    console.log('Signicat/createSession() params:', params);
    // inputDataValidator.validateCreateSession(params);

    // get access token
    const accessToken = params.accessToken ? params.accessToken : await obtainAccessToken(params);
    const bearerHeader = 'Bearer ' + accessToken;

    const body = {
      // prefilledInput: {
      //   'nin': '07128312345',
      //   'mobile': '+4799716935',
      //   'email': 'bruce@wayneenterprice.com',
      //   'userName': 'brucewayne',
      //   'dateOfBirth': '1973-12-07'
      // },
      // additionalParameters: {
      //   'sbid_flow': 'QR',
      //   'sbid_end_user_ip': '127.0.0.1'
      // },
      callbackUrls: {
        success: params.redirect_uri,
        abort: params.redirect_uri,
        error: params.redirect_uri
      },
      encryptionPublicKey: config.publicJwk, // await getPublicKey('enc', config.publicEncIdentifier),
      // requestedLoa: 'string',
      // allowedProviders: [
      //   'nbid',
      //   'sbid',
      //   'idin',
      //   'digid',
      //   'eherkenning',
      //   'spid'
      // ],
      language: params.ui_locales,
      flow: 'redirect',
      themeId: 'plusid',
      requestedAttributes: [
        'firstName',
        'lastName',
        'email',
        'dateOfBirth',
        'phoneNumber',
        'address',
        'gender'
      ],
      externalReference: params.state,
      sessionLifetime: 60
      // requestDomain: 'string'
    };
    console.log('Signicat/createSession() body:', body);
    // const stringifiedBody = qs.stringify(body);
    // console.log('Signicat/createSession() stringifiedBody:', stringifiedBody);

    const options = {
      ...httpOptions,
      headers: { Authorization: bearerHeader }
    };
    console.log('Signicat/createSession() options:', options);

    // do request
    const postResponse = await axios.post(SIGNICAT_API_ENDPOINT + 'sessions', body, options);
    console.log('Signicat/createSession() headers of response:', postResponse.headers);
    console.log('Signicat/createSession() data of response:', postResponse.data);

    // decrypt data
    let decryptedResponse = postResponse.data;
    if (config.FTN || postResponse.headers['content-type'] === 'application/jose') {
      // decrypt the response
      console.log('Signicat/createSession() try to decrypt the payload');
      decryptedResponse = await decryptToken(decryptedResponse);
      try {
        decryptedResponse = JSON.parse(decryptedResponse);
      } catch (err) {
        console.error('Signicat/createSession() ERROR in JSON parsing decryptedResponse; returning original! err:', err);;
      }
      // console.log('Signicat/createSession() decryptedResponse:', decryptedResponse);
    }

    // include nonce in response
    decryptedResponse.nonce = params.nonce;

    return decryptedResponse;
  }

  async function getSession(params) {
    console.log('Signicat/getSession() params:', params);
    // inputDataValidator.validateGetSession(params);

    const bearer = params.accessToken;
    const options = {
      ...httpOptions,
      headers: { Authorization: 'Bearer ' + bearer }
    };

    const getResponse = await axios.get(SIGNICAT_API_ENDPOINT + 'sessions/' + params.sessionId, options);
    console.log('Signicat/getSession() headers of response:', getResponse.headers);
    console.log('Signicat/getSession() data of response:', getResponse.data);

    // decrypt data
    let decryptedResponse = getResponse.data;
    if (config.FTN || getResponse.headers['content-type'] === 'application/jose') {
      // decrypt the response
      console.log('Signicat/getSession() try to decrypt the payload');
      decryptedResponse = await decryptToken(decryptedResponse);
      try {
        decryptedResponse = JSON.parse(decryptedResponse);
      } catch (err) {
        console.error('Signicat/getSession() ERROR in JSON parsing decryptedResponse; returning original! err:', err);;
      }
      console.log('Signicat/getSession() decryptedResponse:', decryptedResponse);
    }
    return decryptedResponse;
  }

  return {
    getAuthorizationUrl,
    postAccessToken,
    getUserInfo,
    apiUrl,
    getPublicKey,
    verifyTokenSignature,
    decryptToken,
    // Signicat API; added 20230921
    obtainAccessToken,
    createSession,
    getSession
  };
};
