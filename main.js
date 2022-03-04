const jsonServer = require('json-server')
const server = jsonServer.create()
const router = jsonServer.router('db.json')
const fs = require('fs')
const middlewares = jsonServer.defaults()
const queryString = require('query-string');
const lowdb = JSON.parse(fs.readFileSync('./db.json', 'UTF-8'))
const jwt = require('jsonwebtoken')

// Set default middlewares (logger, static, cors and no-cache)
server.use(middlewares)

// Add custom routes before JSON Server router
server.get('/echo', (req, res) => {
  res.jsonp(req.query)
})

// To handle POST, PUT and PATCH you need to use a body-parser
// You can use the one used by JSON Server
server.use(jsonServer.bodyParser)
server.use((req, res, next) => {
  if (req.method === 'POST') {
    req.body.createdAt = Date.now()
    req.body.updatedAt = Date.now()
  } else if (req.method === 'PATCH') {
    req.body.updatedAt = Date.now();
  }
  // Continue to JSON Server router
  next()
})

// Custom output for LIST with pagination
router.render = (req, res) => {
  // Check GET with pagination
  // If yes, custom output
  const headers = res.getHeaders();

  const totalCountHeader = headers['x-total-count'];
  
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401
    const message = 'Error in authorization format'
    res.status(status).json({status, message, error: true})
    return
  }
  try {
    let verifyTokenResult;
     verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

     if (verifyTokenResult instanceof Error) {
       const status = 401
       const message = 'Access token not provided'
       return res.status(status).json({status, message, error: true})
     }
  } catch (err) {
    const status = 401
    const message = 'Error access_token is revoked'
    return res.status(status).json({status, message, error: true})
  }

  if (req.method === 'GET' && totalCountHeader) {
    const queryParams = queryString.parse(req._parsedUrl.query);

    const result = {
      data: res.locals.data,
      pagination: {
        _page: Number.parseInt(queryParams._page) || 1,
        _limit: Number.parseInt(queryParams._limit) || 10,
        _total: Number.parseInt(totalCountHeader),
      },
    };

    return res.jsonp(result);
  }

  // Otherwise, keep default behavior
  res.jsonp(res.locals.data);
};

const SECRET_KEY = 'luvya'

const EXPIRES_IN = '1h'

// Create a token from a payload 
function createToken(payload){
  return jwt.sign(payload, SECRET_KEY, {expiresIn: EXPIRES_IN})
}

// Verify the token 
function verifyToken(token){
  return  jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ?  decode : err)
}
// Check if the user exists in database
function isAuthenticated({username, password}){
  return lowdb.users.find(user => user.username === username && user.password === password);
}
// Login to one of the users from ./users.json
server.post('/api/auth/login', (req, res) => {
  const {username, password} = req.body;
  if (!isAuthenticated({username, password})) {
    const status = 401;
    const response = {
      error: true,
      status,
      message: 'Incorrect username or password'
    }
    res.status(status).json(response)
    return
  }
  const infoUser = isAuthenticated({username, password});
  const access_token = createToken(infoUser)
  res.status(200).json({access_token})
})

// Check authen
server.post('/api/auth/check-auth', (req, res) => {
  const {access_token} = req.body;
  const verifyTokenResult = verifyToken(access_token);
  if (verifyTokenResult instanceof Error) {
    const status = 401;
    const response = {
      error: true,
      status,
      message: 'Incorrect acces token'
    }
    res.status(status).json(response)
    return
  }
  res.status(200).json({
    error: false,
    status: 200,
    message: 'Authen success',
    data: verifyTokenResult
  })
})

// Use default router
server.use('/api', router)
server.listen(3001, () => {
  console.log('JSON Server is running')
})