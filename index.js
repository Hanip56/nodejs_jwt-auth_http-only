require("dotenv").config();
require("colors");
const express = require("express");
const cors = require("cors");
const { corsOptions } = require("./config/corsOptions");
const { credentials } = require("./middleware/credentials");
const { errorHandler } = require("./middleware/errorMiddleware");
const cookieParser = require("cookie-parser");
const { connectDB } = require("./config/db");

const port = process.env.PORT || 5000;
const app = express();
connectDB();

// if the server allows the request to include credentials add this
app.use(credentials);

app.use(cookieParser());
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(express.static("./public"));

app.use("/api/auth", require("./routes/authRoutes"));

app.use(errorHandler);

app.listen(port, () => {
  console.log(`Server is listening on port: ${port}`.yellow.underline);
});
