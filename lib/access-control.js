
/*!
 * Connect - access-control
 * Copyright(c) 2011 Nicolas Chambrier
 * MIT Licensed
 */

/**
 * Expose the middleware
 */
exports = module.exports = accessControl;

/**
 * Paths to ignore, default "/favicon.ico"
 */
exports.ignore = ["/favicon.ico"];

/**
 * Global protection
 */
exports.secure = [];
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
 * User with roles
 */
var User = exports.User = function (loggedin, roles, context) {
  if (!context.req || !context.superAdmin || !context.save || !context.initialize) throw new Error("Invalid user context");
  this.loggedin = loggedin;
  this.roles = roles;
  this.context = context;
}

User.prototype.save = function (callback) {
  this.context.save(this.context.req, this.loggedin, this.roles, callback);
}

/**
 * Utility function for User's roles
 */
function addOrRemoveRoles(user, roles, add) {
  if (roles instanceof Array) {
    for (var i=0; i<roles.length; i++) {
      addOrRemoveRoles(user, roles[i], add);
    }
  } else {
    var i = user.roles.indexOf(roles);
    if (!~i && add) user.roles.push(roles);
    else if (~i && !add) user.roles.splice(i, 1);
  }
}

/**
 * Add role to user
 */
User.prototype.grant = function (roles, callback) {
  addOrRemoveRoles(this, roles, true);
  this.save(callback);
}

/**
 * Remove roles from user
 */
User.prototype.revoke = function (roles, callback) {
  addOrRemoveRoles(this, roles, false);
  this.save(callback);
}

/**
 * Remove all roles from user
 */
User.prototype.revokeAll = function (callback) {
  this.roles = [];
  this.save(callback);
}

/**
 * Is super admin ?
 */
User.prototype.isSuperAdmin = function () {
  return this.has([this.context.superAdmin]);
}

/**
 * List roles
 */
User.prototype.getRoles = function () {
  return this.roles;
}

/**
 * Check roles combination
 */
User.prototype.has = function (roles, disjunctive) {
  if (this.isSuperAdmin()) return true;
  if (roles instanceof Array) {
    for (var i=0; i<roles.length; i++) {
      var has = this.has(roles[i], !disjunctive);
      if (disjunctive && !has) /* false AND ... = false */ return false;
      if (!disjunctive && has) /* true OR ... = true */ return true;
    }
    // if disjunctive, we're here because they're all true = true
    // if conjunctive, we're here because they're all false = false
    return disjunctive;
  } else {
    return ~this.roles.indexOf(roles);
  }
}

/**
 * Logs user in, and initialize roles
 */
User.prototype.login = function (callback) {
  var self = this;
  self.loggedin = true;
  self.context.initialize(self.context.req, function (roles) {
    if (roles) self.roles = roles;
    self.save(callback);
  });
}

/**
 * Checks if user is logged in
 */
User.prototype.isLoggedIn = function () {
  return this.loggedin;
}

/**
 * Logs user out, clearing credentials
 */
User.prototype.logout = function (callback) {
  this.loggedin = false;
  this.roles = [];
  this.save(callback);
}

/**
 * role based access control middleware for connect
 *
 * Usage:
 * 
 * var ac = require('connect-access-control');
 * app.use(accessControl({
 *   ignore: [ ... routes to ignore, strings or regular expressions ... ] // default = "/favicon"
 *   secure: [ ... routes to protect ... ] // global protection: default = none, use global regexp /.+/ to protect all pages
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
 * To enable global protection, define accessControl.secure or option secure.
 * These pages will be protected based on accessControl.requiredLoggedIn or option requiredLoggedIn, and accessControl.requiredRoles or option requiredRoles.

 * Global default configuration:
 *
 *  - accessControl.secure will be merged with option
 *  - accessControl.ignore will be merged with option
 *  - accessControl.superAdmin will be replaced by option
 *  - accessControl.limitedAccessCallback will be replaced by option
 *  - accessControl.loginPath will define the path to login form if you use default notLoggedInCallback
 *  - accessControl.notLoggedInCallback will be replaced by option
 *  - accessControl.initialize will be replaced by option
 *  - accessControl.retrieve will be replaced by option
 *  - accessControl.save will be replaced by option
 *
 * Even if you enabled global protection, you can anyway protect your routes one by one, using accessControl.secure middleware:
 *
 * app.get('/account',   [accessControl.secure(true) <- require logged in ],    function (req, res) { ... });
 * app.get('/admin',     [accessControl.secureRoles('admin')],                  function (req, res) { ... });
 * app.get('/moderator', [accessControl.secureRoles([['admin', 'moderator']])], function (req, res) { ... });
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
  var ignore = mergeArrays(exports.ignore, options.ignore || [])
    , secure = mergeArrays(exports.secure, options.secure || [])
    , requiredLoggedIn = ('undefined' == typeof options.requiredLoggedIn) ? exports.requiredLoggedIn : options.requiredLoggedIn
    , requiredRoles = mergeArrays(exports.requiredRoles, options.requiredRoles || [])
    , superAdmin = mergeArrays(exports.superAdmin, options.superAdmin || [])
    , initialize = options.initialize || exports.initialize
    , retrieve = options.retrieve || exports.retrieve
    , save = options.save || exports.save
    ;
  
  return function (req, res, next) {
    // Ignore path ?
    if (matchPath(req.pathname, ignore)) return next();
    // Populate req.user
    retrieve(req, function (loggedin, roles) {
      if ('undefined' != typeof roles && roles !== null) {
        try {
          req.user = new User(loggedin, roles, {
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
      if (req.user && matchPath(req.pathname, secure)) {
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
    else if (roles === true && req.user.isLoggedIn()) next();
    else if (roles instanceof Array && req.user.has(roles)) next();
    else if (roles === true) exports.notLoggedInCallback(req, res, next);
    else exports.limitedAccessCallback(req, res, next);
  }
}

/**
 * Utility function to merge arrays and return a new copy
 */
function mergeArrays () {
  result = [];
  for (var i=0; i<arguments.length; i++) {
    for (var j=0; j<arguments[i].length; j++) {
      if (!~result.indexOf(arguments[i][j])) {
        result.push(arguments[i][j]);
      }
    }
  }
  return result;
}

/**
 * Utility function to check if a path is matched against a list of templates
 */
function matchPath (path, paths) {
  for (var i=0; i<paths.length; i++) {
    if ((typeof paths[i] == 'string' && path == paths[i]) || (paths[i] instanceof RegExp && paths[i].test(path))) return true;
  }
  return false;
}
