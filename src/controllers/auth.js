/*
  ztncui - ZeroTier network controller UI
  Copyright (C) 2017-2021  Key Networks (https://key-networks.com)
  Licensed under GPLv3 - see LICENSE for details.
*/

const argon2 = require('argon2');
const usersController = require('../controllers/usersController');

const hash_check = async function (user, password) {
  let verified = false;
  try {
    var users = await usersController.get_users();
  } catch (err) {
    throw err;
  }
  try {
    verified = await argon2.verify(users[user].hash, password);
  } catch (err) {
    throw err;
  }
  return verified;
}

exports.hasRightsForNetwork = hasRightsForNetwork;
function hasRightsForNetwork(user, nwid) {
  return isSuperAdmin(user) || user.networks.includes(nwid);
}

exports.isSuperAdmin = isSuperAdmin;
function isSuperAdmin(user) {
  return user.role == 'superadmin';
}

exports.authenticate = async function (name, pass, callback) {
  try {
    var users = await usersController.get_users();
  } catch (err) {
    throw err;
  }
  let user = users[name];
  if (!user) return callback(new Error('cannot find user'));
  let verified = await hash_check(name, pass);
  if (verified) {
    user = { ...user };
    user.role = 'superadmin';
    user.networks = [];
    return callback(null, user);
  } else {
    return callback(new Error('invalid password'));
  }
}

exports.restrict = function (req, res, next) {
  if (req.session.user) {
    next();
  } else {
    const error = 'Access denied! (Login required)';
    req.session.error = error;
    res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
}

/** @type {import('express').RequestHandler} */
exports.restrictNetwork = function (req, res, next) {
  const { nwid } = req.params;
  if (hasRightsForNetwork(req.session.user, nwid)) {
    next();
  } else {
    const error = 'Access denied! (No permission to access this network)';
    res.render('error', { error });
  }
}

exports.restrictSuperAdmin = function (req, res, next) {
  if (isSuperAdmin(req.session.user)) {
    next();
  } else {
    const error = 'Access denied! (Super admin required)';
    res.render('error', { error });
  }
}

// OpenID Connect (OIDC) Auth:

const { Issuer, generators } = require('openid-client')

const {
  BASE_URL,
  AUTH_OIDC_ISSUER,
  AUTH_OIDC_CLIENT_ID,
  AUTH_OIDC_CLIENT_SECRET,
  AUTH_OIDC_ONLY,
} = process.env;

const useOidc = !!AUTH_OIDC_ISSUER;
const callbackUrl = BASE_URL + '/login_oidc_cb';

exports.oidcAvailable = useOidc;
exports.oidcOnly = AUTH_OIDC_ONLY === 'true';

const oidcClient = !useOidc ? null : (async () => {
  const issuer = await Issuer.discover(AUTH_OIDC_ISSUER);
  const client = new issuer.Client({
    client_id: AUTH_OIDC_CLIENT_ID,
    client_secret: AUTH_OIDC_CLIENT_SECRET,
    redirect_uris: [callbackUrl],
    response_types: ['code'],
  });
  return client;
})()

/** @type {import('express').RequestHandler} */
exports.oidcLogin = async (req, res) => {
  // TODO
  const client = await oidcClient;
  const nonce = generators.nonce();
  const url = client.authorizationUrl({
    scope: 'openid email profile',
    response_mode: 'form_post',
    nonce,
  });
  req.session.nonce = nonce;
  res.redirect(url);
};


/** @type {import('express').RequestHandler} */
exports.oidcCallback = async (req, res) => {
  try {
    const client = await oidcClient;
    const { nonce } = req.session;
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(callbackUrl, params, { nonce });
    const claims = tokenSet.claims();
    console.log('validated ID Token claims %j', claims);
    const user = userFromClaims(claims);
    if (user.role != 'superadmin' && user.networks.length === 0) {
      res.status(500).render('error', { error: 'user has no permission' });
      return;
    }
    req.session.user = user;
    res.redirect('/controller');
  } catch (error) {
    console.error(error);
    res.status(500).render('error', { error: 'oidc error' });
  }
};

/**
 * @param {import('openid-client').IdTokenClaims} claims 
 */
function userFromClaims(claims) {
  const name = claims.email || claims.preferred_username;
  const roles = claims.ztncui_roles;
  let role = 'admin';
  const networks = [];
  for (const r of roles) {
    const [type, arg1, ...rest] = r.split('-');
    if (type == 'role') {
      role = arg1;
    } else if (type == 'nwid') {
      networks.push(...rest);
    } else {
      throw new Error('unknown role ' + r);
    }
  }
  return { name, role, networks }
}
