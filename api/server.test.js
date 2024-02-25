const request = require('supertest');
const server = require('./server');
const db = require('../data/dbConfig');
const knexConfig = require('../knexfile').testing;
const knex = require('knex')(knexConfig);
const bcrypt = require('bcryptjs');
const { JWT_SECRET } = require("./secrets/index");
const jwt = require('jsonwebtoken')
const Jokes = require('../api/jokes/jokes-data');


beforeAll(async () => {
  await knex.migrate.latest();
});

afterAll(async () => {
  await knex.destroy();
});


describe('[POST] /register', () => {
  beforeEach(async () => {
    await db('users')
  })

  it('on successful register of new user a hashed password is in response body', async () => {
    const newUser = { username: 'testuser', password: 'testpassword' };

    const res = await request(server)
      .post('/api/auth/register')
      .send(newUser);

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('username', 'testuser');
    expect(res.body).not.toHaveProperty('password', 'testpassword');

    const user = await db('users').where('id', res.body.id).first();
    const isPasswordCorrect = await bcrypt.compare('testpassword', user.password);
    expect(isPasswordCorrect).toBe(true);
  })

  it('should return 400 Bad Request if username is taken', async () => {
    await db('users').truncate();
    await db('users').insert({ username: 'testuser', password: 'hashedpassword' });
  
    const newUser = { username: 'testuser', password: 'testpassword' };
    const res = await request(server)
      .post('/api/auth/register')
      .send(newUser);
  
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('message', 'username taken');
  });
})

describe('[POST] /login', () => {
  beforeEach(async () => {
    await db('users').truncate()
  })

  it('on successful login response body includes a message and token', async () => {
    const hash = await bcrypt.hash('testpassword', 8)
    await db('users').insert({ username: 'testuser', password: hash })

    const res = await request(server)
      .post('/api/auth/login')
      .send({ username: 'testuser', password: 'testpassword' })

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('message', 'welcome, testuser')
    expect(res.body).toHaveProperty('token')
    
  })

  it('on invalid username response body includes message', async () => {
    
    const res = await request(server)
    .post('/api/auth/login')
    .send({ username: 'nonexistentuser', password: 'testpassword' })

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('message', 'invalid credentials')
  })
})

describe('[GET] /api/jokes', () => {
  let token;

beforeEach(async () => {
  const user = { username: 'testuser', id: '1' };
  token = jwt.sign({ 
    username: user.username,
    id: user.id
  }, JWT_SECRET, { expiresIn: '1h' });
})
it('should return status 200 and all jokes when authenticated', async () => {
  const res = await request(server)
    .get('/api/jokes')
    .set('Authorization', `${token}`);

  expect(res.status).toBe(200);
  expect(res.body).toEqual(Jokes);
})

it('should return status 401 when not authenticated', async () => {
  const res = await request(server).get('/api/jokes');
  expect(res.status).toBe(401)
})

it('responds with a "token required" message on missing token', async () => {
  const res = await request(server).get('/api/jokes')
  expect(res.status).toBe(401)
  expect(res.body.message).toBe('token required');
});

it('responds with a "token invalid" message on invalid token', async () => {
  const token = jwt.sign({ username: 'testuser' }, 'invalidsecret');
  const res = await request(server)
    .get('/api/jokes')
    .send('Authorization', `${token}`)
  expect(res.status).toBe(401)
  expect(res.body.message).toBe('token invalid');
});

});





