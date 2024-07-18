const jwt = require ('jsonwebtoken');
const dotenv = require ('dotenv');
dotenv.config ();
const JWT_SECRET = process.env.JWT_SECRET;
const authMiddleware = (req, res, next) => {
  console.log ('In middleware');
  const authHeader = req.headers.authorization;
  console.log (authHeader);
  if (!authHeader || !authHeader.startsWith ('Bearer ')) {
    return res.status (403).json ({});
  }
  const token = authHeader.split (' ')[1];
  console.log ('token is:', token);
  try {
    const decode = jwt.verify (token, JWT_SECRET);
    req.userId = decode.userId;
    console.log ('userid is:', req.userId);
    next ();
  } catch (err) {
    return res.status (403).json ({
        "message":"error"
    });
  }
};
module.exports = {
  authMiddleware,
};
