# passport-http-api-token-bearer


HTTP Bearer authentication strategy for [Passport](http://passportjs.org/).

This module lets you authenticate HTTP requests using bearer tokens in your Node.js
applications.  Bearer tokens are typically used protect API endpoints, and are
often issued using OAuth 2.0.  You have to pass token in req.header, req.body and req.query, (priority is as mentioned)

By plugging into Passport, bearer token support can be easily and unobtrusively
integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-http-api-token-bearer

## Usage

#### Configure Strategy

The HTTP Bearer authentication strategy authenticates users using a bearer
token.  The strategy requires a `verify` callback, which accepts that
credential and calls `done` providing a user.  Optional `info` can be passed,
typically including associated scope or object.

    This strategy will use default token name, which is `access_token`
    passport.use(new BearerStrategy(
      function(token, done) {
        User.findOne({ token: token }, function (err, user) {
          if (err) { return done(err); }
          if (!user) { return done(null, false); }
          return done(null, user, { scope: 'all' });
        });
      }
    ));
    
    OR
    
    passport.use(new BearerStrategy({
            access_token: 'x-access-token'      /// you can define custom access_token name here,
        },
      function(token, done) {
        User.findOne({ token: token }, function (err, user) {
          if (err) { return done(err); }
          if (!user) { return done(null, false, {statusCode:404, error: true, message: "Not Found"}); }
          return done(null, user, { scope: 'all' });
        });
      }
    ));      

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'token-bearer'` strategy, to
authenticate requests.  Requests containing bearer tokens do not require session
support, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/profile', 
      passport.authenticate('token-bearer', { session: false }),
      function(req, res) {
        res.json(req.user);
      });

      app.all('/api/*', function(req, res, next){
          passport.authenticate('token-bearer', { session: false }, function(err, user, info) {
            if (info.statusCode == 200) return next();
            else if (!info.statusCode) return res.status(401).json({ error: info });
            return res.status(info.statusCode).json({ error: info.error, message: info.message, result: info.result });
          })(req, res);
      });

## Credits

  - [Arsalan Bilal](http://github.com/mabc224)

## License

[The MIT License](http://opensource.org/licenses/MIT)
