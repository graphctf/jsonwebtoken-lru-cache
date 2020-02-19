const jwt = require('jsonwebtoken');
const JwtLru = require('../');

const secret = 'foobar';
const secretWrong = 'wrong';

const algorithm = 'HS256';

const payload = { success: true };
const payloadString = 'hi';

const dateOrig = 1000000;
const dateFnOrig = Date.now;
Date.now = () => dateOrig;

const delta = 100;
const timestamp = Math.floor(Date.now() / 1000);
const timestampPast = timestamp - delta;
const timestampFuture = timestamp + delta;
const timestampPastMore = timestampPast - delta;
const timestampFutureMore = timestampFuture + delta;

const jwtRandomValid = () => jwt.sign( {...payload, rand: Math.random()}, secret, { algorithm });
const jwtNoExpiration = jwt.sign(payload, secret, { algorithm });
const jwtNbfPast = jwt.sign({ ...payload, nbf: timestampPast }, secret, { algorithm });
const jwtNbfFuture = jwt.sign({ ...payload, nbf: timestampFuture }, secret, { algorithm });
const jwtExpPast = jwt.sign({ ...payload, exp: timestampPast }, secret, { algorithm });
const jwtExpFuture = jwt.sign({ ...payload, exp: timestampFuture }, secret, { algorithm });
const jwtWrongSecret = jwt.sign(payload, secretWrong, { algorithm });
const jwtString = jwt.sign(payloadString, secret, { algorithm });

const aud = 'foo';
const audWrong = 'bar';
const jwtAud = jwt.sign(payload, secret, { algorithm, audience: aud });
const jwtWrongAud = jwt.sign(payload, secret, { algorithm, audience: audWrong });

const lru = new JwtLru(1024*1024, secret);
const lruAud = new JwtLru(1024*1024, secret, { audience: aud });

it('should succeed non-expiration jwt', async () => {
  expect((await lru.verifyAsync(jwtNoExpiration)).success).toBe(true);
});

it('should be callable with a callback when fetching from cache', () => {
  lru.verify(jwtNoExpiration, false, (error, result) => {
    expect(result.success).toBe(true);
    expect(error).toBe(null);
  });
});

it('should be callable synchronously when not fetching from cache', () => {
  expect(lru.verify(jwtRandomValid()).success).toBe(true);
});

it('should be callable with a callback when not fetching from cache', () => {
  lru.verify(jwtRandomValid(), false, (error, result) => {
    expect(result.success).toBe(true);
    expect(error).toBe(null);
  });
});

it('should be callable synchronously when fetching from cache', () => {
  expect(lru.verify(jwtNoExpiration).success).toBe(true);
});

it('should throw synchronously', () => {
  expect(() => lru.verify(jwtWrongSecret)).toThrowError();
});

it('should throw callbacks', () => {
  lru.verify(jwtWrongSecret, false, (err, res) => {
    expect(err).not.toBeNull();
  });
});

it('should support non-object payloads', async () => {
  expect(await lru.verifyAsync(jwtString)).toBe(payloadString);
});

it('should support fetcing the full object from the cache', async () => {
  expect(await lru.verifyAsync(jwtString, true)).toHaveProperty('header');
});

it('should support fetcing the full object from generation', async () => {
  expect(await lru.verifyAsync(jwtRandomValid(), true)).toHaveProperty('header');
});

it('should support fetcing the full object synchronously from generation', () => {
  expect(lru.verify(jwtRandomValid(), true)).toHaveProperty('header');
});

it('should succeed with matching option', async () => {
  expect((await lruAud.verifyAsync(jwtAud)).success).toBe(true);
});

it('should fail with non-matching option', async () => {
  await expect(lruAud.verifyAsync(jwtWrongAud)).rejects.toThrowError();
});

it('should throw on invalid key', async () => {
  await expect(lru.verifyAsync(jwtWrongSecret)).rejects.toThrowError();
});


it('should throw on encryption key in second param', async () => {
  await expect(lru.verifyAsync(jwtNoExpiration, secret)).rejects.toThrowError()
})

it('should cache successful validations', () => {
  expect(lru.has(jwtNoExpiration)).toBe(true);
});

it('should cache unsuccessful validations', () => {
  expect(lru.has(jwtWrongSecret)).toBe(true)
});

it('should succeed on past nbf', async () => {
  expect((await lru.verifyAsync(jwtNbfPast)).success).toBe(true)
});

it('should succeed on future exp', async () => {
  expect((await lru.verifyAsync(jwtExpFuture)).success).toBe(true);
});

it('should throw on future nbf', async () => {
  await expect(lru.verifyAsync(jwtNbfFuture)).rejects.toThrowError();
});

it('should throw on past exp', async () => {
  await expect(lru.verifyAsync(jwtExpPast)).rejects.toThrowError();
});

it('should cache exp for the correct time', () => {
  expect(lru.getMaxAge(jwtExpFuture)).toBe(delta);
});

it('should cache nbf for the correct time', () => {
  expect(lru.getMaxAge(jwtNbfFuture)).toBe(delta);
});

it('should return null for non-existent max-age', () => {
  expect(lru.getMaxAge('hi')).toBeNull();
});

it('should not have cached items past their expiry date', async () => {
  Date.now = () => timestampFutureMore * 1000;
  expect(lru.has(jwtExpFuture)).toBe(false);
  await expect(lru.verifyAsync(jwtExpFuture)).rejects.toThrowError();
  Date.now = () => dateOrig;
});
afterAll(() => {
  Date.now = dateFnOrig;
});
