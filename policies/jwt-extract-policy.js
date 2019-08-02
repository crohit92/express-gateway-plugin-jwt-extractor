const jwt = require('jsonwebtoken');
const fs = require('fs');
module.exports = {
  name: 'jwt-extract',
  schema: {
    $id: '9208b270-4946-484c-b6ef-fdd928c6da66',
    properties: {
      publicKeyFile: {
        type: 'string',
      },
      forwardHeaders: {
        type: 'object'
      }
    },
    required: ['publicKeyFile']
  },
  policy: (actionParams) => {
    return (req, res, next) => {
      const authHeader = req.headers['authorization'];
      if (authHeader) {
        const token = authHeader.replace('Bearer ', '');
        const publicKey = fs.readFileSync(`${__dirname}/../../../${actionParams.publicKeyFile}`);
        jwt.verify(token, publicKey, {
          algorithms: ['RS256']
        }, (err, decodedToken) => {
          if (err) {
            res.status(500).json({ error: err });
          } else {
            /**
             * add headers for the downstream service
             */
            if (actionParams.hasOwnProperty('forwardHeaders')) {
              const forwardHeaders = actionParams.forwardHeaders;
              for (let targetHeaderName in forwardHeaders) {
                req.headers[targetHeaderName] = decodedToken[forwardHeaders[targetHeaderName]];
              }
            }
            next();
          }
        })
      }
      else {
        // next({error:'Authorization header not available'});
        res.status(500).json({
          error: 'Authorization header not available'
        })
      }
      // eslint-disable-next-line no-console

    };
  }
};
