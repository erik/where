/* jshint esversion: 6 */

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const express = require('express');
const session = require('express-session');

require('dotenv').config();

const redis = require('redis').createClient();

// TODO: Probably some kind of error handling here.
redis.on('error', (err) => console.error(`redis error: ${err}`));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_SECRET_ID,
    callbackURL: process.env.BASE_URL + '/auth/google/callback'
}, (_1, _2, profile, done) => {
    console.log('received profile: ', profile);

    if (profile.emails.some(e => e.value === process.env.GOOGLE_EMAIL)) {
        return done(null, profile.id);
    }

    return done('who are you');
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    saveUnitialized: true,
    resave: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/login', (req, res) => {
    res.contentType('text/html');
    res.send(`<a href="/auth/google">log in</a>`);
});

app.get('/auth/google', passport.authenticate('google', {
    scope: ['email']
}));

app.get('/auth/google/callback',
        passport.authenticate('google', { failureRedirect: '/login' }),
        (req, res) => {
            req.session.loggedIn = true;
            res.redirect('/');
        });

app.get('/', (req, res) => {
    res.send('hi');
});

app.get('/api/where', (req, res) => {
    redis.lrange('where', 0, -1, (err, data) => {
        if (err !== null) {
            console.error('lrange failed', err);
            return res.abort(500);
        }

        return res.send({
            where: data.map(d => JSON.parse(d))
        });
    });
});

app.post('/api/here', (req, res) => {
    if (!res.session.loggedIn) return res.abort(403);

    const point = JSON.stringify({
        lat: req.body.lat,
        lng: req.body.lng,
        comment: req.body.comment,
        ts: new Date()
    });

    return redis.lpush('where', point, (err) => {
        if (err !== null) {
            console.error('lpush failed', err);
            res.abort(500);
        } else {
            res.send({});
        }
    });
});

app.listen(process.env.PORT);
