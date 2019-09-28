/* jshint esversion: 6 */

const bodyParser = require('body-parser');
const escapeHtml = require('escape-html');
const express = require('express');
const expressHandlebars = require('express-handlebars');
const handlebars = require('handlebars');
const morgan = require('morgan');
const moment = require('moment');
const passport = require('passport');
const passportGoogle = require('passport-google-oauth');
const redis = require('redis').createClient();
const cookieSession = require('cookie-session');

require('dotenv').config();

redis.on('error', err => console.error(`redis error: ${err}`));

const app = express();

app.use(morgan('common'));
app.use(bodyParser.urlencoded({ extended: true }));
app.engine(
  'html',
  expressHandlebars({
    defaultLayout: false,
    helpers: {
      humanize: ts => moment(ts).fromNow(),
      json: val => new handlebars.SafeString(JSON.stringify(val)),
      unsafe: val => new handlebars.SafeString(val)
    }
  })
);
app.set('view engine', 'handlebars');

app.use(
  cookieSession({
    secret: process.env.SESSION_SECRET,
    maxAge: 365 * 24 * 60 * 60 * 1000  // ~1 year
  })
);

passport.use(
  new passportGoogle.OAuth2Strategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_SECRET_ID,
      callbackURL: process.env.BASE_URL + '/who/google/callback'
    },
    (_1, _2, { emails, id }, done) => {
      if (emails.some(e => e.value === process.env.GOOGLE_EMAIL)) {
        return done(null, id);
      }

      return done('who are you');
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(passport.initialize());
app.use(passport.session());

function requireAuth(req, res, next) {
  if (!req.session.loggedIn) {
    return res.redirect('/who');
  }

  return next();
}

// Where are you.
function where() {
  return new Promise((resolve, reject) => {
    redis.hgetall('where', (err, data) => {
      if (err !== null) {
        console.error('hgetall failed', err);
        return reject(err);
      }

      return resolve(
        Object.values(data || {})
          .map(d => JSON.parse(d))
          .sort((a, b) => -a.ts.localeCompare(b.ts))
      );
    });
  });
}

function setWhere(key, point) {
  return new Promise((resolve, reject) => {
    redis.hset('where', key, point, err => {
      if (err !== null) {
        console.error('hset failed', err);
        return reject(err);
      }

      return resolve(null);
    });
  });
}

function setWhy(why) {
  return new Promise((resolve, reject) => {
    if ((why || '')) {
      redis.set('why', why, err => err ? reject(err) : resolve(null));
    } else {
      resolve(null);
    }
  });
}

// Why are you there.
function why() {
  return new Promise((resolve, reject) => {
    redis.get('why', (err, data) => {
      if (err !== null) {
        console.error('get failed', err);
        return reject(err);
      }

      return resolve(data);
    });
  });
}

// You are here.
function here(lat, lng, comment, why) {
  const createdAt = new Date();
  const redisKey = createdAt.toISOString();

  const point = JSON.stringify({
    lat,
    lng,
    why,
    comment: escapeHtml(comment),
    ts: createdAt,
    key: redisKey
  });

  return Promise.all([
    setWhere(redisKey, point),
    setWhy(why)
  ]);
}

app.get('/', (req, res) => {
  where()
    .then(points => {
      res.render('where.html', { who: process.env.WHO, points });
    })
    .catch(() => res.sendStatus(500));
});

const passportAuthenticate = passport.authenticate('google', {
  scope: ['email'],
  failureRedirect: '/who'
});

app.get('/who', passportAuthenticate);

app.get('/who/google/callback', passportAuthenticate, (req, res) => {
  req.session.loggedIn = true;
  res.redirect('/here');
});

app.get('/here', requireAuth, (req, res) => {
  Promise.all([where(), why()])
    .then(([points, why]) => res.render('here.html', { points, why }))
    .catch(() => res.sendStatus(500));
});

app.post('/here', requireAuth, (req, res) => {
  here(
    req.body.lat,
    req.body.lng,
    req.body.comment,
    req.body.why
  ).then(() => res.redirect('/'))
   .catch(() => res.sendStatus(500));
});

app.post('/here/:id/delete', requireAuth, (req, res) => {
  if (!req.params.id) return res.sendStatus(400);

  redis.hdel('where', req.params.id, err => {
    if (err !== null) {
      console.error('hdel failed', err);
      return res.sendStatus(500);
    }

    return res.redirect('/here');
  });
});

app.post('/here/:id/edit', requireAuth, (req, res) => {
  if (!req.params.id) return res.sendStatus(400);

  redis.hget('where', req.params.id, (err, data) => {
    if (err !== null) {
      console.error('hget failed', err);
      return res.sendStatus(500);
    }

    let pt = JSON.parse(data);
    pt.comment = req.body.comment ? escapeHtml(req.body.comment) : pt.comment;
    pt.why = req.body.why ? req.body.why : pt.why;

    setWhere(req.params.id, JSON.stringify(pt))
      .then(() => res.redirect('/here'))
      .catch(() => res.sendStatus(500));
  })
});

app.listen(process.env.PORT);
