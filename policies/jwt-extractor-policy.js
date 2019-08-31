/**
 * ```yaml
 * policies:
 *     - cors:
 *         - action:
 *             origin: "*"
 *             methods: "GET,HEAD,PUT,PATCH,POST,DELETE"
 *             credentials: true
 *             exposedHeaders: ["db-name"]
 *     - jwt-extractor:
 *         - action:
 *             tokenSources:
 *               - source: "cookies"
 *                 key: "token"
 *               - source: "headers"
 *                 key: "authorization"
 *             publicKeyFile: ./config/keys/public.pem
 *             forwardHeaders:
 *               db-name: org.dbName
 * ```
 */
const jwt = require('jsonwebtoken');
const fs = require('fs');
module.exports = {
  name: 'jwt-extractor',
  schema: {
    $id: '9208b270-4946-484c-b6ef-fdd928c6da66',
    properties: {
      publicKeyFile: {
        type: 'string'
      },
      forwardHeaders: {
        type: 'object'
      },
      tokenSources: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            source: {
              type: 'string',
              enum: ['headers', 'cookies']
            },
            key: {
              type: 'string'
            }
          },
          required: ['source', 'key']
        }
      }
    },
    required: ['publicKeyFile', 'tokenSources']
  },
  policy: actionParams => {
    return (req, res, next) => {
      let token;
      actionParams.tokenSources.forEach(ts => {
        if (ts.source === 'headers') {
          const authHeader = req.headers[ts.key];
          if (authHeader) {
            token = authHeader.replace('Bearer ', '');
          }
        } else if (ts.source === 'cookies') {
          token = req.headers.cookie
            .split(';')
            .filter(c => c.match(new RegExp(actionParams.source.key)))[0]
            .split('=')[1]
            .trim();
        }
      });

      if (token) {
        const publicKey = fs.readFileSync(
          `${__dirname}/../../../${actionParams.publicKeyFile}`
        );
        jwt.verify(
          token,
          publicKey,
          {
            algorithms: ['RS256']
          },
          (err, decodedToken) => {
            if (err) {
              res.status(500).json({ error: err });
            } else {
              /**
               * add headers for the downstream service
               */
              if (actionParams.hasOwnProperty('forwardHeaders')) {
                const forwardHeaders = actionParams.forwardHeaders;
                for (let targetHeaderName in forwardHeaders) {
                  req.headers[targetHeaderName] = forwardHeaders[
                    targetHeaderName
                  ]
                    .split('.')
                    .reduce((parent, key) => parent[key], decodedToken);
                }
              }
              next();
            }
          }
        );
      } else {
        res.status(500).json({
          error: 'Authorization token not available'
        });
      }
      // eslint-disable-next-line no-console
    };
  }
};
