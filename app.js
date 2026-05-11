require('./utils.js');
require('dotenv').config(); 
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');
const saltRounds = 10;


const app = express();
const port = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; // 1 hour in milliseconds

const path = require('path');
app.set('view engine', 'ejs');
app.use(express.static('public'));


const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const {database} = include('databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('Users');

app.use(express.urlencoded({extended: false}));
app.use(express.json());

function getRandomInt(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}


var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
  secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

// Basic Route
app.get('/', (req, res) => {
  res.render('home', { 
    title: 'Home', 
    authenticated: req.session.authenticated, 
    username: req.session.username,
    errorMessage: req.session.errorMessage });
});

app.get('/signup', (req, res) => {
  res.render('signUp', { 
    title: 'Signup', 
    errorMessage: req.session.errorMessage });
});

app.post('/signingup', async (req, res) => {
  const { username, email, password } = req.body;
  
  const schema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const valuation = schema.validate({ username, email, password });
  if (valuation.error) {
    console.error(valuation.error.details[0].message); // see exact error
    req.session.errorMessage = 'Error: Incorrect inputted format';
    res.render('signUp', { title: 'Signup', 
      errorMessage: req.session.errorMessage });
    return;
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: 'user'});
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { 
    title: 'Login', 
    errorMessage: req.session.errorMessage });
});

app.post('/loggingin', async (req, res) => {
  const { email, password } = req.body;
  
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error) {
    req.session.errorMessage = 'Error: Incorrect inputted format';
    res.redirect('/login');
    return;
  }

  const result = await userCollection.find({ email: email }).project({email: 1, username: 1, password: 1, _id: 1}).toArray();

  if (result.length != 1) {
    req.session.errorMessage = 'Error: Invalid email or password';
    res.redirect('/login');
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.email = email;
    req.session.errorMessage = '';
    req.session.username = result[0].username;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
    return;
  } else {
    req.session.errorMessage = 'Error: Invalid email or password';
    res.redirect('/login');
    return;
  }
});

app.get('/members', (req, res) => {
  if (req.session.authenticated) {
    res.render('members', { 
      title: 'Members Area', 
      username: req.session.username, 
      errorMessage: req.session.errorMessage });
  } else {
    req.session.errorMessage = 'Error: You must be logged in to access the members area';
    res.redirect('/');
  }
});

app.get('/admin', async (req, res) => {
  if (!req.session.authenticated || req.session.user_type !== 'admin') {
    req.session.errorMessage = 'Error: Admins only';
    return res.redirect('/');
  }
  const users = await userCollection.find({}).project({username: 1, email: 1, user_type: 1, _id: 0}).toArray();
  res.render('admin', { 
    title: 'Admin Area', 
    errorMessage: req.session.errorMessage, 
    users: users
   });
});

app.post('/promote', async (req, res) => {
  if (req.session.authenticated && req.session.user_type === 'admin') {
    const { email } = req.body;
    await userCollection.updateOne({ email: email }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
  } else {     
    req.session.errorMessage = 'Error: You must be logged in to an admin account to use this action';
    res.redirect('/');
  }
});

app.post('/demote', async (req, res) => {
  if (req.session.authenticated && req.session.user_type === 'admin') {
    const { email } = req.body;
    await userCollection.updateOne({ email: email }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
  } else {
    req.session.errorMessage = 'Error: You must be logged in to an admin account to use this action';
    res.redirect('/');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.use((req, res) => {
  res.render('404', { 
    title: '404 Not Found' });
});

// Start Server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});