const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const protect = asyncHandler(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];

      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

      req.user = await User.findById(decoded.id);
      next();
    } catch (error) {
      console.log(error);
      res.status(403);
      throw new Error("Forbidden");
    }
  }

  if (!token) {
    res.status(403);
    throw new Error("Not authorized, no token");
  }
});

module.exports = { protect };
