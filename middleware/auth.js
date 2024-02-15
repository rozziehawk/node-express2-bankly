/** Middleware for handling req authorization for routes. */

const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../config');

/** Authorization Middleware: Requires user is logged in. */

function requireLogin(req, res, next) {
  try {
    
    //console.log("inside requireLogin, req:");
    //console.log(req);

    // BUG 01: not sure where cur_username comes from. Used req.body.username insteead
    //if (!req.curr_username) {
    if (req.body.username) {
      return next();
    } else {
      return next({ status: 401, message: 'Unauthorized' });
    }
  } catch (err) {
    return next(err);
  }
}

/** Authorization Middleware: Requires user is logged in and is staff. */

function requireAdmin(req, res, next) {
  try {
    // BUG 02: the following conditional needs to be in the negative and use req.body 
    //if (!req.curr_admin) {
    if(!req.body.admin) {
      return next();
    } else {
      return next({ status: 401, message: 'Unauthorized' });
    }
  } catch (err) {
    return next(err);
  }
}

/** Authentication Middleware: put user on request
 *
 * If there is a token, verify it, get payload (username/admin),
 * and store the username/admin on the request, so other middleware/routes
 * can use it.
 *
 * It's fine if there's no token---if not, don't set anything on the
 * request.
 *
 * If the token is invalid, an error will be raised.
 *
 **/

function authUser(req, res, next) {
  try {
    const token = req.body._token || req.query._token;
    //console.log("req.body:");
    //console.log(req.body);
    //console.log("Inside authUser, Token:");
    //console.log(token);
    if (token) {
      let payload = jwt.decode(token);
      req.curr_username = payload.username;
      req.curr_admin = payload.admin;

    }
    return next();
  } catch (err) {
    err.status = 401;
    return next(err);
  }
} // end

module.exports = {
  requireLogin,
  requireAdmin,
  authUser
};
