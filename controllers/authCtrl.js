const User = require("../models/User");
const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");

const sendUserData = (user) => ({
  _id: user?._id,
  username: user?.username,
  email: user?.email,
  fullname: user?.fullname,
  slug: user?.slug,
  profilePicture: user?.profilePicture,
  createdAt: user?.createdAt,
  updatedAt: user?.updatedAt,
});
const cookieName = "authJWTCookie";
// const sendUserData = (user) => user;

// @desc    register user
// @route   POST /api/auth
// @access  PUBLIC
const register = asyncHandler(async (req, res, next) => {
  const { email, username, password } = req.body;

  // Make sure all the field required is added
  if (!username || !email || !password) {
    res.status(400);
    throw new Error(
      "Please add all required fields *username *email *password"
    );
  }

  //   check if the user exist
  const userExist = await User.findOne({ email });

  if (userExist) {
    res.status(409);
    throw new Error("User already exist");
  }

  try {
    const user = await User.create({
      username,
      email,
      password,
    });

    const accessToken = user.getAccessToken();

    const refreshToken = user.getRefreshToken();

    user.refreshToken = [refreshToken];

    await user.save();

    // send http-only cookie
    res.cookie(cookieName, refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      user: sendUserData(user),
      token: accessToken,
    });
  } catch (error) {
    res.status(500);
    next(error);
  }
});

// @desc    login user
// @route   POST /api/auth/login
// @access  PUBLIC
const login = asyncHandler(async (req, res, next) => {
  const cookies = req.cookies;
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400);
    throw new Error("Please add all fields *email *password");
  }

  const user = await User.findOne({ email }).select("+password +refreshToken");

  if (!user) {
    res.status(401);
    throw new Error("User not exist");
  }

  const isMatch = await user.matchPassword(password);

  if (!isMatch) {
    res.status(401);
    throw new Error("Wrong password");
  }

  const accessToken = user.getAccessToken();
  const newRefreshToken = user.getRefreshToken();

  // get rid of the old cookies
  let newRefreshTokenArray = !cookies?.[cookieName]
    ? user.refreshToken
    : user.refreshToken.filter((rt) => rt !== cookies?.[cookieName]);

  if (cookies?.[cookieName]) {
    const refreshToken = cookies[cookieName];
    const foundToken = await User.findOne({ refreshToken });

    if (!foundToken) {
      newRefreshTokenArray = [];
    }

    res.clearCookie(cookieName, {
      httpOnly: true,
      sameSite: "none",
      secure: true,
    });
  }

  user.refreshToken = [...newRefreshTokenArray, newRefreshToken];
  await user.save();

  res.cookie(cookieName, newRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.status(200).json({
    user: sendUserData(user),
    token: accessToken,
  });
});

// @desc    refresh token
// @route   GET /api/auth/refresh
// @access  PRIVATE
const refreshToken = async (req, res, next) => {
  const cookies = req.cookies;
  if (!cookies?.[cookieName]) {
    res.status(401);
    return next(new Error("Unauthorized"));
  }

  const refreshToken = cookies[cookieName];
  res.clearCookie(cookieName, {
    httpOnly: true,
    sameSite: "none",
    secure: true,
  });

  const userExist = await User.findOne({ refreshToken }).select(
    "+refreshToken"
  );

  // Detected refresh token reuse!
  if (!userExist) {
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      async (err, decoded) => {
        if (err) {
          res.status(403);
          return next(new Error("Forbidden"));
        } //Forbidden

        try {
          // Delete refresh tokens of hacked user
          const hackedUser = await User.findById(decoded.id);
          hackedUser.refreshToken = [];
          const result = await hackedUser.save();
        } catch (error) {
          console.log(error);
          return next(error);
        }
      }
    );
    res.status(403);
    return next(new Error("Forbidden")); //Forbidden
  }

  const newRefreshTokenArray = userExist.refreshToken.filter(
    (rt) => rt !== refreshToken
  );

  // evaluate jwt
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) {
        // expired refresh token
        userExist.refreshToken = [...newRefreshTokenArray];
        const result = await userExist.save();
      }
      if (err || userExist.id !== decoded.id) {
        res.status(403);
        return next(new Error("Forbidden"));
      }

      // Refresh token was still valid
      const accessToken = userExist.getAccessToken();

      const newRefreshToken = userExist.getRefreshToken();
      // Saving refreshToken with current user
      userExist.refreshToken = [...newRefreshTokenArray, newRefreshToken];
      const result = await userExist.save();

      // Creates Secure Cookie with refresh token
      res.cookie(cookieName, newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        user: sendUserData(userExist),
        token: accessToken,
      });
    }
  );
};

// @desc    logout user
// @route   GET /api/auth/logout
// @access  PRIVATE
const logout = async (req, res) => {
  // On client, also delete the accessToken

  const cookies = req.cookies;
  if (!cookies?.[cookieName]) return res.sendStatus(204); //No content
  const refreshToken = cookies[cookieName];

  // Is refreshToken in db?
  const foundUser = await User.findOne({ refreshToken }).select(
    "+refreshToken"
  );
  if (!foundUser) {
    res.clearCookie(cookieName, {
      httpOnly: true,
      sameSite: "none",
      secure: true,
    });
    return res.sendStatus(204);
  }

  // Delete refreshToken in db
  foundUser.refreshToken = foundUser.refreshToken.filter(
    (rt) => rt !== refreshToken
  );
  await foundUser.save();

  res.clearCookie(cookieName, {
    httpOnly: true,
    sameSite: "none",
    secure: true,
  });
  res.sendStatus(204);
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
};
