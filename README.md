Connect Access Control middleware
=================================

License MIT - Copyright Nicolas Chambrier <naholyr@gmail.com>

What's inside?
--------------

* You can use this module with Express or any other Connect-based application
* You'll find an application middleware to configure access control layer
* You'll be able to globally protect a list of paths in your application, or...
* ... protect any action, one by one, using the route middleware

Installation
------------

From NPM (easiest and best way):

    npm install connect-access-control

From Git (if you want to contribute, or get a dev version):

    git clone http://github.com/naholyr/connect-access-control.git node_modules/connect-access-control

Enable access control in your application
-----------------------------------------

Load the middleware:

    var accessControl = require('connect-access-control');

Enable access control in your application:

    app.use(accessControl(options));

If you use default ``retrieve`` and ``save`` options, you must have enabled session support *before* enabling access control:

    app.use(connect.middleware.session(...));
    app.use(accessControl(...));

Access credentials
------------------

The middleware will populate request with a new key "user" (see option ``reqKey`` to customize this). ``req.user`` will provide the following methods:

* ``grant(roles, callback)`` add role(s) to user, and call callback() after credentials are saved
* ``revoke(roles, callback)`` remove role(s) from user, and call callback() after credentials are saved
* ``revokeAll(callback)`` remove all roles from user, and call callback() after credentials are saved
* ``isSuperAdmin()`` checks if user has a super-admin role
* ``getRoles()`` returns the list of user's roles
* ``has(roles)`` checks if user matches the given combination of roles (see "Checking roles")
* ``login(callback)`` marks user as logged in, retrieve his initial roles (see option ``initialize``), and call callback() after credentials are saved
* ``logout(callback)`` marks user as logged out, and call callback() after credentials are saved
* ``isLoggedIn()`` checks if user has been marked as logged in

Configuration
-------------

Global options:

* ``accessControl.securedPaths`` list of automatically secured paths (called "global protection"), each one can be a string (exact path) or a regular expression
* ``accessControl.requiredLoggedIn`` set to true if global protection should require to be logged in
* ``accessControl.requiredRoles`` roles that must be required for globally protected pages
* ``accessControl.ignoredPaths`` list of paths that won't trigger the access control (no ``req.user`` created), each one can be a string (exact path) or a regular expression
* ``accessControl.superAdmin`` list the roles that will be considered as super-admin roles
* ``accessControl.limitedAccessCallback`` will be called for secured pages with required roles that are not matched (``function(req,res,next)``)
* ``accessControl.notLoggedInCallback`` will be called for secured pages requiring logged in user (``function(req,res,next)``)
* ``accessControl.loginPath`` the default ``notLoggedInCallback`` will redirect to this path
* ``accessControl.initialize`` will retrieve initial roles from user as soon as he logs in (``function(req,callback)``, where ``callback`` is ``function(roles or null if nothing loaded)``), default does not initialize anything
* ``accessControl.retrieve`` will retrieve current roles for user (``function(req,callback)`` where ``callback`` is ``function(loggedin,roles)``), default will retrieve from session
* ``accessControl.save`` will save current roles from user (``function(req,loggedin,roles,callback)``) where ``callback`` is ``function()``), default will save to session
* ``accessControl.reqKey`` will allow you to customize how req will be populated, default is "user" to create a ``req.user`` object

Instance options:

* ``ignoredPaths`` will be merged with global option ``ignoredPaths``
* ``securedPaths`` will be merged with global option ``securedPaths``
* ``requiredLoggedIn`` will replace global option ``requiredLoggedIn``
* ``requiredRoles`` will replace global option ``requiredRoles``
* ``superAdmin`` will be merged with global option ``superAdmin``
* ``initialize`` will replace global option ``initialize``
* ``retrieve`` will replace global option ``retrieve``
* ``save`` will replace global option ``save``

Secure your application (Express samples)
-----------------------------------------

Globally (this is not the best way in my opinion, but maybe the easiest at beginning):

	// Global protection
    accessControl.securedPaths.push('/private');
    // Globally protected pages require login
    accessControl.requiredLoggedIn = true;
    // Globally protected pages require role "authorized"
    accessControl.requiredRoles.push("authorized");

Per page:

    // Require logged in
    app.get('/private', accessControl.secure(true), function (req, res) { ... });
    // Require role "admin" or "moderator"
    app.get('/moderate', accessControl.secure([["admin", "moderator"]]), function (req, res) { ... });

Look at the sample Express application provided in the ``sample`` directory.

Checking roles
--------------

The way roles are required is directly inspired by symfony's credentials system. You can imbricate arrays to alternate AND and OR operations.

Here are some examples that will explain this system more easily than the full explanation ;)

    ["role1", "role2]                           role1 AND role2
    [["role1", "role2"]]                        role1 OR role2
    ["role1", ["role2", "role3"]]               role1 AND (role2 OR role3)
    ["role1", ["role2", ["role3", "role4"]]]    role1 AND (role2 OR (role3 AND role4))

As you see, the first level of array = AND operation, then each time you add a level you alternate: OR, then AND, then OR, etc...

With this simple system you can declare any complex combinations of roles to secure your pages.

Version history
---------------

* ``1.0.0`` 2011-07-30: Initial release
