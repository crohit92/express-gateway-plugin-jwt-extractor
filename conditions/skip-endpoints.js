module.exports = {
  name: 'skipEndpoints',
  handler: function(req, { endpoints }) {
    const matchingEndpointIndex = endpoints.findIndex(e =>
      req.path.match(e.path)
    );
    if (matchingEndpointIndex >= 0) {
      return !endpoints[matchingEndpointIndex].method.match(
        new RegExp(req.method, 'ig')
      );
    }
    return true;
  }
};
