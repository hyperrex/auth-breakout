const model = require('../models/users_model');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const signJwt = promisify(jwt.sign);
const bcrypt = require('bcryptjs');
const authenticate = require('../utils/authenticate');
const env = require('../../env');
let usersValidators = require('../utils/validators/users_validator');

// ===============================================
// USER CONTROLLERS
// ===============================================

const getAllUsers = async (req, res, next) => {
  let authorization = authenticate(req.headers.authorization);
  if (authorization.error) {
    return next(authorization);
  }

  let promise = model.getAllUsers();

  promise.then(result => {
    res.status(200).json(result);
  });

  promise.catch(error => {
    next(error);
  });
};

const getUserById = async (req, res, next) => {
  let authorization = authenticate(req.headers.authorization);
  if (authorization.error) {
    return next(authorization);
  }

  let promise = model.getUserById(req.params.id);
  let { message, error } = await promise;
  if (message == 'user not found' || error == 'error retrieving user') {
    return next(await promise);
  }

  promise.then(async result => {
    delete result.hashedPassword;

    let [songs, followers, following] = await Promise.all([
      model.getUserSongs(req.params.id),
      model.getFollowers(result.id),
      model.getFollowing(result.id)
    ]);

    result.userSongs = songs;
    result.followers = followers;
    result.following = following;

    res.status(200).json(result);
  });

  promise.catch(error => {
    next(error);
  });
};

const getUserByUsername = (req, res, next) => {
  let promise = model.getUserByUsername(req.params.username.toLowerCase());

  promise.then(result => {
    return result.error ? next(result) : res.status(200).json(result);
  });

  promise.catch(error => {
    next(error);
  });
};

const loginUser = async (req, res, next) => {
  const credentials = req.body;
  // console.log(credentials);

  // find user in database using username off of request body
  const user = await model.getUserByUsername(
    credentials.username.toLowerCase()
  );
  // console.log(user)

  // if no match, return error
  if (user.error) {
    // console.log(user.error)
    return next(user);
  }

  // if user found, compare payload password with result from getByUsername with bcrypt.js
  // console.log('user object >>>>>>>>>', user)
  // console.log('credentials >>>>>>>>>', credentials)
  const isValid = await bcrypt.compare(
    credentials.password,
    user.hashedPassword
  );
  // console.log('isValid >>>>>>>', isValid)

  // if password is valid omit password from user response
  if (isValid) {
    // console.log('user.hashedPassword >>>>>>>', user.hashedPassword)
    delete user.hashedPassword;
    // console.log('user.hashedPassword >>>>>>>', user.hashedPassword)
    // create JWT token
    const timeIssued = Math.floor(Date.now() / 1000);
    const timeExpires = timeIssued + 86400 * 28;
    const token = await signJwt(
      {
        iss: 'thatSong',
        aud: 'thatSong',
        iat: timeIssued,
        exp: timeExpires,
        identity: user.id
      },
      env.JWT_KEY
    );
    // console.log('token >>>>>>>>>', token);
    // console.log('token decoded >>>>>>>>>', jwt.decode(token));

  // attach token to response
  // or attach token via headers (the correct way ;)
  // respond with status 200 and user object
  res.status(200).set({ 'authorization': token }).json(user);
  }

  //respond with 400 and error message if not found
  next({ error: 'username or password is incorrect', status: 400})
};

const createUser = async (req, res, next) => {
  let payload = req.body;
  let isValid = usersValidators.createUser(payload);
  if (!isValid) return next(isValid);

  payload.profile_pic =
    'https://cdn1.iconfinder.com/data/icons/ios-edge-line-12/25/User-Square-512.png';

  let doesUsernameExist = await model.getUserByUsername(
    payload.username.toLowerCase()
  );

  let doesEmailExist = await model.getUserByUsername(
    payload.email.toLowerCase()
  );

  if (doesEmailExist.email) {
    return next({ error: 'that email is taken', status: '404' });
  }

  if (doesUsernameExist.username) {
    return next({ error: 'that username is taken', status: '404' });
  }

  let promise = model.createUser(payload);

  promise.then(result => {
    delete result[0].hashedPassword;
    return result.error ? next(result) : res.status(201).json(result);
  });

  promise.catch(error => {
    next(error);
  });
};

const deleteUser = (req, res, next) => {
  let id = Number(req.params.id);

  let promise = model.deleteUser(id);

  promise.then(result => {
    res.status(201).json(result);
  });

  promise.catch(error => {
    next(error);
  });
};

const updateUser = (req, res, next) => {
  let id = Number(req.params.id);
  let payload = req.body;
  let promise = model.updateUser(id, payload);

  promise.then(result => {
    res.status(201).json(result);
  });

  promise.catch(error => {
    next(error);
  });
};

const getToken = (req, res, next) => {
  let authorization = authenticate(req.headers.authorization);
  if (authorization.error) {
    return next(authorization);
  }
  res.status(200).json({ message: 'token valid' });
};

module.exports = {
  getAllUsers,
  getUserById,
  loginUser,
  getUserByUsername,
  createUser,
  deleteUser,
  updateUser,
  getToken
};

/*
{
	"username": "djshmarl",
	"password": "yahoo"
}
*/
