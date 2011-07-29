
/*!
 * Connect - access-control
 * Copyright(c) 2011 Nicolas Chambrier
 * MIT Licensed
 */

/**
 * Dependencies
 */
const User = require('./user')
    , utils = require('./utils')

/**
 * Expose the middleware
 */
exports = module.exports = accessControl;

/**
 * Paths to ignored, default "/favicon.ico"
 */
exports.ignoredPaths = ["/favicon.ico"];

/**
 * Global protection
 */
exports.securedPaths = [];
exports.requiredLoggedIn = false;
exports.requiredRoles = [];

/**
 * Middleware called when user does not match required roles
 */
exports.limitedAccessCallback = function (req, res) {
  res.writeHead(403, {"Content-Type": "text/plain"});
  res.end("Forbidden");
}

/**
 * Middleware called when user is not logged in
 */
exports.loginPath = "/login"; // Path to login form
exports.notLoggedInCallback = function (req, res) {
  var url = exports.loginPath;
  if (!~url.indexOf('://')) {
    url = 'http' + (req.connection.encrypted ? 's' : '') + '://' + req.headers.host + url;
  }
  res.writeHead(302, {"Location": url, "Content-Type": "text/html"});
  res.end('<p>Redirecting to <a href="' + url + '">' + url + '</a></p>');
}

/**
 * All those roles will match any other role
 */
exports.superAdmin = ["superadmin"];

/**
 * req's key to populate
 */
exports.reqKey = "user";

/**
 * Load credentials from session
 */
exports.retrieve = function (req, callback) {
  var data = {};
  if (req.session) {
    data = req.session._credentials_data_ || data;
    callback(data.loggedin || false, data.roles || []);
  } else {
    callback(false, null);
  }
}

/**
 * Save credentials to session
 */
exports.save = function (req, loggedin, roles, callback) {
  if (req.session) {
    req.session._credentials_data_ = {
      "loggedin": loggedin,
      "roles":    roles
    };
  }
  callback();
}

/**
 * Initialize roles when user logs in
 */
exports.initialize = function (req, callback) {
  callback(null);
}

/**
 * role based access control middleware for connect
 *
 * Usage:
 * 
 * var ac = require('connect-access-control');
 * app.use(accessControl({
 *   ignoredPaths: [ ... routes to ignore, strings or regular expressions ... ] // default = "/favicon"
 *   securedPaths: [ ... routes to protect ... ] // global protection: default = none, use global regexp /.+/ to protect all pages
 *   requiredLoggedIn: false // only if you chose global protection
 *   requiredRoles: [] // only if you chose global protection
 *   superAdmin: ["superadmin"] // define roles that will match every constraint
 *   initialize: function (req, callback) { ... look for credentials depending on req.session or whatever ... then call callback(roles) ... } // default = none
 *   retrieve: function (req, callback) { ... load credentials ... then call callback(loggedIn, roles = null if load failed) ... } // default = load from session
 *   save: function (req, loggedIn, roles, callback) { ... save credentials ... then call callback() ... } // default = save to session
 * }));
 * 
 * All configuration options are optional.
 *
 * To enable global protection, define accessControl.securedPaths or option securedPaths.
 * These pages will be protected based on accessControl.requiredLoggedIn or option requiredLoggedIn, and accessControl.requiredRoles or option requiredRoles.

 * Global default configuration:
 *
 *  - accessControl.securedPaths will be merged with option
 *  - accessControl.ignoredPaths will be merged with option
 *  - accessControl.requiredLoggedIn
 *  - accessControl.requiredRoles
 *  - accessControl.superAdmin will be replaced by option
 *  - accessControl.limitedAccessCallback will be replaced by option
 *  - accessControl.loginPath will define the path to login form if you use default notLoggedInCallback
 *  - accessControl.notLoggedInCallback will be replaced by option
 *  - accessControl.initialize will be replaced by option
 *  - accessControl.retrieve will be replaced by option
 *  - accessControl.save will be replaced by option
 *  - accessControl.reqKey
 *
 * Even if you enabled global protection, you can anyway protect your routes one by one, using accessControl.secure middleware:
 *
 * app.get('/account',   [accessControl.secure(true) <- require logged in ],  function (req, res) { ... });
 * app.get('/admin',     [accessControl.secure('admin')],                     function (req, res) { ... });
 * app.get('/moderator', [accessControl.secure([['admin', 'moderator']])],    function (req, res) { ... });
 *
 * Requiring roles:
 *
 *  - "role" : will match if user has "role" amongst his credentials
 *  - ["role1", "role2"] : will match "role1" AND "role2"
 *  - ["role1", ["role2", "role3"]] : will match "role1" AND ("role2" OR "role3")
 *  - etc... you can imbricate arrays to alternate AND/OR and create any complex combinations of roles to match
 *
 * Access credentials from your actions:
 * connect-access-control defines "req.user", instance of accessControl.User
 *  - req.user.grant(roles, callback)   // will add role(s) and save
 *  - req.user.revoke(roles, callback)  // will remove role(s) and save
 *  - req.user.revokeAll(callback)      // will revoke all roles and save
 *  - req.user.getRoles()               // retrieve all roles
 *  - req.user.has(roles)               // will check if user has roles combination
 *  - req.user.login(callback)          // will call your "initialize" method to eventually load credentials depending on data, and save
 *  - req.user.isLoggedIn()             // checks if user is logged in
 *  - req.user.logout(callback)         // Logs user out and save
 *  - req.user.isSuperAdmin()           // Has a superadmin role
 */
function accessControl (options) {
  options = options || {};
  var ignoredPaths = utils.merge(exports.ignoredPaths, options.ignoredPaths || [])
    , securedPaths = utils.merge(exports.securedPaths, options.securedPaths || [])
    , requiredLoggedIn = ('undefined' == typeof options.requiredLoggedIn) ? exports.requiredLoggedIn : options.requiredLoggedIn
    , requiredRoles = options.requiredRoles || exports.requiredRoles
    , superAdmin = utils.merge(exports.superAdmin, options.superAdmin || [])
    , initialize = options.initialize || exports.initialize
    , retrieve = options.retrieve || exports.retrieve
    , save = options.save || exports.save
    ;
  
  return function (req, res, next) {
    // ignored path ?
    if (utils.match(req.pathname, ignoredPaths)) return next();
    // Populate req.user
    retrieve(req, function (loggedin, roles) {
      if ('undefined' != typeof roles && roles !== null) {
        try {
          req[exports.reqKey] = new User(loggedin, roles, {
            "req": req,
            "save": save,
            "superAdmin": superAdmin,
            "initialize": initialize
          });
        } catch (e) {
          return next(e);
        }
      }
      // Protect path ?
      if (req[reqKey] && utils.match(req.pathname, securedPaths)) {
        exports.secure(requiredLoggedIn, function (req, res) {
          exports.secure(requiredRoles, next);
        });
      } else {
        next();
      }
    });
  }
}

/**
 * Require user to be logged in
 */
exports.secure = function (roles) {
  return function (req, res, next) {
    if (!roles || (roles instanceof Array && roles.length == 0)) next();
    else if (roles === true) {
      if (req[reqKey].isLoggedIn()) next();
      else exports.notLoggedInCallback(req, res, next);
    } else {
      if (req[reqKey].has(roles)) next();
      else exports.limitedAccessCallback(req, res, next);
    }
  }
}
