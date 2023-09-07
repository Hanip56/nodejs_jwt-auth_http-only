const errorHandler = (err, req, res, next) => {
  let statusCode = res.statusCode !== 200 ? res.statusCode : 500;

  let errorMessage = err.message;

  if (err.code === 11000) {
    errorMessage = "There was duplicate key Error";
    statusCode = 400;
  }

  res.status(statusCode);
  res.json({
    message: errorMessage,
    stack: process.env.NODE_ENV === "production" ? undefined : err.stack,
  });
};

module.exports = {
  errorHandler,
};
