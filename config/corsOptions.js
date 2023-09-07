const allowOrigins = require("./allowOrigins");

const corsOptions = {
  origin: (origin, cb) => {
    if (allowOrigins.indexOf(origin) !== -1 || !origin) {
      cb(null, true);
    } else {
      cb("Not allowed by CORS");
    }
  },
};

module.exports = { corsOptions };
