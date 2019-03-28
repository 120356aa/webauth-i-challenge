const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const PORT = 5000;

const db = require('./data/dbConfig.js');
const Users = require('./users/users-modal.js');

const server = express();

server.use(helmet());
server.use(express.json());

function restricted(req, res, next) {
  const { username, password } = req.headers;

  if (username && password ) {
    Users
    .findBy({username})
    .first()
    .then(user => {
      if ( user && bcrypt.compareSync(password, user.password)) {
        next();
      } else {
        res.status(401).json({message: 'Invalid credentials'});
      }
    })
    .catch(err => res.status(500).json(err));
  } else {
    res.status(400).json({message: 'Missing Credentials'});
  }
}

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => res.json(users))
    .catch(err => res.send(err));
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10);

  user.password = hash;
  
  Users
    .add(user)
    .then(saved => res.status(201).json(saved))
    .catch(err => res.status(500).json(err));
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users
    .findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => res.status(500).json(error));
});

server.listen(PORT, console.log(PORT));