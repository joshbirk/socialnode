var fs = require("fs")
var ssl_options = {
  key: fs.readFileSync('privatekey.pem'),
  cert: fs.readFileSync('certificate.pem')
};
     
var port = process.env.PORT || 3000;
var express = require('express');
var ejs = require('ejs');
var passport = require('passport')
  , ForceDotComStrategy = require('passport-forcedotcom').Strategy
  , TwitterStrategy = require('passport-twitter').Strategy
  , FacebookStrategy = require('passport-facebook').Strategy;
var lazyproxy = require('lazy-proxy');

//define passport usage
passport.use(new ForceDotComStrategy({
    clientID: '{YOURCONSUMERKEY}',
    clientSecret: '{YOURPRIVATEKEY}',
    callbackURL: 'https://127.0.0.1:'+port+'/token'
  },
  function(token, tokenSecret, profile, done) {
    console.log(profile);
    return done(null, profile);
  }
));

passport.use(new TwitterStrategy({
  consumerKey: '{YOURCONSUMERKEY}',
  consumerSecret: '{YOURPRIVATEKEY}',
  callbackURL: 'https://127.0.0.1:'+port+'/twitter-token' //this will need to be dealt with
  }, function(token, tokenSecret, profile, done) {
    profile.access_token = token;
    process.nextTick(function () {
      return done(null, profile);
    });
  }));

passport.use(new FacebookStrategy({
    clientID: '{YOURCONSUMERKEY}',
    clientSecret: '{YOURPRIVATEKEY}',
    callbackURL: 'https://127.0.0.1:'+port+'/facebook-token'
  },
  function(accessToken, refreshToken, profile, done) {
    profile.access_token = accessToken;
    process.nextTick(function () {
      return done(null, profile);
    });
  }
));

//define REST proxy options based on logged in user
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(null); }
  res.redirect('/error')
}

function checkSession(req) {
  var logins = {
    fdc_user : false,
    fdc_user_id : null,
    fb_user : false,
    fb_user_id : null,
    tw_user : false,
    tw_user_id : null
    }

  if(req.session["forcedotcom"]) { logins.fdc_user = true; logins.fdc_user_id = req.session["forcedotcom"]["id"].split("/")[5]; }
  if(req.session["facebook"]) { logins.fb_user = true; logins.fb_user_id = req.session["facebook"]["id"];}
  if(req.session["twitter"]) { logins.tw_user = true; logins.tw_user_id = req.session["twitter"]["id"]; }
    
  return logins;
}

//configure, route and start express
var app = express.createServer(ssl_options);
app.configure(function() {
  app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'thissecretrocks' }));
  app.use(express.static(__dirname + '/public'));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
});

app.set('view engine', 'ejs');
app.set('view options', {
  layout: false,
  open: '{{',
  close: '}}'
});

app.get('/', 
  function(req, res) {
    res.render("index",checkSession(req));
  });

app.get('/login', passport.authenticate('forcedotcom'));
app.get('/token', 
  passport.authenticate('forcedotcom', { failureRedirect: '/error' }),
  function(req, res){
    req.session["forcedotcom"] = req.session["passport"]["user"];
    res.render("index",checkSession(req));
  });

app.get('/twitter-login', passport.authenticate('twitter'));
app.get('/twitter-token',
 passport.authenticate('twitter', { failureRedirect: '/error' }),
  function(req, res){
    req.session["twitter"] = req.session["passport"]["user"];
    res.render("index",checkSession(req));
  });

app.get('/facebook-login', passport.authenticate('facebook',{ scope: 'read_stream' }));
app.get('/facebook-token',
  passport.authenticate('facebook', { failureRedirect: '/error' }),
  function(req, res){
    req.session["facebook"] = req.session["passport"]["user"];
    res.render("index",checkSession(req));
  });


app.get('/error', function(req, res){
  res.send('An error has occured.');
  });

app.all('/:label/:mode/*',
  ensureAuthenticated,
  function(req, res) {
    console.log(req.session);
    
    //forcedotcom
    if(req.session["forcedotcom"] && req.params.label == "fdc") {
      var restOptions = {
        useHTTPS : true,
        host : req.session["forcedotcom"].instance_url.replace('https://',''),
        headers: {
            'Authorization': 'OAuth '+req.session["forcedotcom"].access_token,
            'Accept':'application/jsonrequest',
            'Cache-Control':'no-cache,no-store,must-revalidate'
          }
      }

      lazyproxy.send(restOptions,req,res);
    }

    //twitter
    if(req.session["twitter"] && req.params.label == "tw") {
      var restOptions = {
        useHTTPS : true,
        host : 'api.twitter.com',
        headers: {
            'Accept':'application/jsonrequest',
            'Cache-Control':'no-cache,no-store,must-revalidate'
          }
      }

      lazyproxy.send(restOptions,req,res);
    }

    //facebook
    if(req.session["facebook"] && req.params.label == "fb") {
      var restOptions = {
        useHTTPS : true,
        host : 'graph.facebook.com',
        headers: {
            'Authorization': 'OAuth '+req.session["passport"]["user"].access_token,
            'Accept':'application/jsonrequest',
            'Cache-Control':'no-cache,no-store,must-revalidate'
          }
      }

       lazyproxy.send(restOptions,req,res);
    }

  });

app.get('/*',function(req, res) {
  res.render(req.url.substring(1,req.url.length)); //really?
})

app.listen(port, function() {
  console.log("Listening on " + port);
});


