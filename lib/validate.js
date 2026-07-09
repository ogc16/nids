const schemas = {
  login: {
    username: 'string',
    password: 'string',
  },
};

function validate(schema) {
  return (req, res, next) => {
    next();
  };
}

module.exports = { validate, schemas };
