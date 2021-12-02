'use strict';

const validator = require('validator');
const urlOptions = {
  protocols: ["https", 'http'],
  require_valid_protocol: true,
  require_protocol: true,
  require_tld: false // for localhost
};

function validateConfig(params) {
  if (!params.requestPromise || !params.client_id || !params.secret) {
    throw new Error('Configuration: requestPromise, client_id and secret are mandatory');
  }
  if(params.FTN && !params.privateJwk) {
    throw new Error('Configuration: privateJwk is required when FTN is enabled');
  }
  if (params.isProd && typeof(params.isProd) !== 'boolean') {
    throw new Error('Configuration: isProd must be a boolean');
  }
}

function validateGetAuthorize(params) {
  if (!params || !params.state || !params.redirect_uri || !params.response_type || !params.scope) {
    throw new Error('Configuration: state, redirect_uri,response_type and scope are mandatory');
  }
  if (!isValidUrl(params.redirect_uri)) {
    throw new Error('Validation: redirect_uri must be a valid http URL');
  }
}

function validatePostToken(params) {
  if (!params || !params.code || !params.grant_type || !params.redirect_uri) {
    throw new Error('Validation: code, grant_type and redirect_uri are mandatory');
  }
  if (!isValidUrl(params.redirect_uri)) {
    throw new Error('Validation: redirect_uri must be a valid http URL');
  }
}

function validateGetUserInfo(params) {
  if (!params || !params.access_token) {
    throw new Error('Validation: access_token is mandatory');
  }
}

function isValidUrl(url) {
  return validator.isURL(url, urlOptions);
}

module.exports = {
  validateConfig,
  validateGetAuthorize,
  validatePostToken,
  validateGetUserInfo,
  isValidUrl
};