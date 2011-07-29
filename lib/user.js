
/**
 * User with roles
 */
var User = module.exports = function (loggedin, roles, context) {
  if (!context.req || !context.superAdmin || !context.save || !context.initialize) throw new Error("Invalid user context");
  this.loggedin = loggedin;
  this.roles = roles;
  this.context = context;
}

/**
 * Save credentials
 */
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
  return this.has([this.context.superAdmin], false);
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
User.prototype.has = function (roles, checkSuperAdmin, disjunctive) {
  if ('undefined' == typeof checkSuperAdmin) checkSuperAdmin = true;
  if ('undefined' == typeof disjunctive) disjunctive = true;
  if (checkSuperAdmin && this.isSuperAdmin()) return true;
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
