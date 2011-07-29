
/**
 * Module dependencies.
 */

var express = require('express');

var app = module.exports = express.createServer();

// Connect Access Control middleware
var accessControl = require('..');

// Configuration

app.configure(function(){
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.static(__dirname + '/public'));

  // Enable sessions, required for access control default storage
  app.use(express.cookieParser());
  app.use(express.session({
    "secret": "some private string"
  }));

  // Enable access control
  app.use(accessControl());

  app.use(app.router);
});

app.configure('development', function(){
  app.use(express.errorHandler({ dumpExceptions: true, showStack: true })); 
});

app.configure('production', function(){
  app.use(express.errorHandler()); 
});

// Routes

// Log in and add credential
app.get('/add/:credential', function (req, res) {
  function redirect() { res.redirect('/'); }
  req.user.grant(req.params.credential, function () {
    if (req.user.isLoggedIn()) redirect();
    else req.user.login(redirect);
  });
});

// Remove credential, and logs out if there is not more credentials
app.get('/remove/:credential', function (req, res) {
  function redirect() { res.redirect('/'); }
  req.user.revoke(req.params.credential, function () {
    if (req.user.getRoles().length == 0) {
      req.user.logout(redirect);
    } else redirect();
  });
});

// Logs out
app.get('/logout', function (req, res) {
  req.user.logout(function () {
    res.redirect('/');
  });
});

// Test access
app.get('/test-public',    [accessControl.secure(false)],         function (req, res) { res.end('yes'); });
app.get('/test-private',   [accessControl.secure(true)],          function (req, res) { res.end('yes'); });
app.get('/test-admin',     [accessControl.secure("admin")],       function (req, res) { res.end('yes'); });
app.get('/test-moderator', [accessControl.secure(["moderator"])], function (req, res) { res.end('yes'); });

// Home
app.get('/', function(req, res){
  res.render('index', {
    title: 'Sample for Connect Access Control',
    user: req.user
  });
});

app.listen(3000);
console.log("Express server listening on port %d in %s mode", app.address().port, app.settings.env);
