const request = require('supertest');
const server = require('./server');
const db = require('../data/dbConfig');
const bcrypt = require('bcryptjs');

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



