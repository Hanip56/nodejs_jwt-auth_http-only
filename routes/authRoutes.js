const {
  register,
  login,
  logout,
  refreshToken,
} = require("../controllers/authCtrl");

const router = require("express").Router();

router.route("/").post(register);
router.route("/login").post(login);
router.route("/logout").get(logout);
router.route("/refresh").get(refreshToken);

module.exports = router;
