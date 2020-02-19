# JWT LRU Cache

![Build Status](https://circleci.com/gh/graphctf/jsonwebtoken-lru-cache.svg?style=svg&circle-token=8f60ff3b7e4b9a7ae1f2a88c2bebf2d44fc1a595)
[Coverage](https://circleci.com/api/v1.1/project/gh/graphctf/jsonwebtoken-lru-cache/latest/artifacts/0/coverage/lcov-report/index.html?circle-token=18e8a179a30990d6c8433396724430ce7ef09d9d)

JWT is (almost always) a signed token, and signatures are intentionally slow (for good reason). If you're using JWTs to
manage stateless authentication or sessions, validations on each request can incur a performance penalty: on the order
of a a few ms per request, depending on a few factors.

This implements a simple LRU cache for verifying JWTs. Cache entries are evicted when the validity of the token could
have changed (such as if a token is invalid because it's before `nbf`, or if a valid token has an `exp`), or in a
least-recently-used order when the number of entries grows beyond the default limit.

## Example Use

```js
const app = require('express')();
const JwtLruCache = require('jsonwebtoken-lru-cache');

const tokenCache = new JwtLruCache(1024*1024*10, process.env.SECRET, { aud: 'urn:myapp' });

app.get('/sync', (req, res) => {
  const payload = tokenCache.validate(req.query.token);
  res.send(`hello, ${payload.name}`);
});

app.get('/async', async (req, res) => {
  const payload = await tokenCache.validateAsync(req.query.token);
  res.send(`hello, ${payload.name}`);
});

app.get('/callback', (req, res) => {
  tokenCache.validate(req.query.token, false, (err, payload) => {
    if (err) res.send('sorry you are not authenticated');
    else res.send(`hello, ${payload.name}`);
  });
});
```

## Functions

- `constructor(numEntries, secret, options)` - All options (except `complete`) need to be set per-cache, not per-call.
- `validate(token, complete, callback)` - Validates the token. This will block unless `callback` is passed.
- `async validateAsync(token, complete)` - Asynchronously validates the token.
- `has(token)` - Checks if the token is in the cache.
