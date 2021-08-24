const url = require('url')

module.exports = Server

function Server({
  model: {
    getAccessToken,
    verifyScope,
    getClient,
    validateScope = (user, client, scope) => scope,
    generateAuthorizationCode = (client, user, scope) => tokenUtil.generateRandomToken(),
  },
  authorizationCodeLifetime = 5 * 60,   // 5 minutes.
}) {

  return {
    authenticate,
    authorize,
    token,
  }

  async function authenticate(scope = undefined, token) {
    const accessToken = await getAccessToken(token)
    if (!accessToken)
      throw new InvalidTokenError('Invalid token: access token is invalid')
    if (!accessToken.user)
      throw new ServerError('Server error: `getAccessToken()` did not return a `user` object')
    if (!(accessToken.accessTokenExpiresAt instanceof Date))
      throw new ServerError('Server error: `accessTokenExpiresAt` must be a Date instance')
    if (accessToken.accessTokenExpiresAt < new Date())
      throw new InvalidTokenError('Invalid token: access token has expired')

    if (scope) {
      const verifiedScope = await verifyScope(accessToken, scope)
      if (!verifiedScope)
        throw new InsufficientScopeError('Insufficient scope: authorized scope is insufficient')
    }

    return accessToken
  }

  async function authorize(clientId, requestedRedirectUri = undefined, token, requestedScope) {

    const expiresAt = new Date()
    expiresAt.setSeconds(expiresAt.getSeconds() + authorizationCodeLifetime)

    const client = getClient(clientId, null)
    if (!client)
      throw new InvalidClientError('Invalid client: client credentials are invalid')
    if (!client.grants)
      throw new InvalidClientError('Invalid client: missing client `grants`')
    if (!_.includes(client.grants, 'authorization_code'))
      throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid')
    if (!client.redirectUris || !client.redirectUris.length || !client.redirectUris[0])
      throw new InvalidClientError('Invalid client: missing client `redirectUri`')
    if (requestedRedirectUri && !_.includes(client.redirectUris, requestedRedirectUri))
      throw new InvalidClientError('Invalid client: `redirect_uri` does not match client value')

    const redirectUri = requestedRedirectUri || client.redirectUris[0]
    try {
      const accessToken = await getAccessToken(token)
      if (!accessToken)
        throw new InvalidTokenError('Invalid token: access token is invalid')
      if (!accessToken.user)
        throw new ServerError('Server error: `getAccessToken()` did not return a `user` object')
      if (!(accessToken.accessTokenExpiresAt instanceof Date))
        throw new ServerError('Server error: `accessTokenExpiresAt` must be a Date instance')
      if (accessToken.accessTokenExpiresAt < new Date())
        throw new InvalidTokenError('Invalid token: access token has expired')

      if (scope) {
        const verifiedScope = await verifyScope(accessToken, scope)
        if (!verifiedScope)
          throw new InsufficientScopeError('Insufficient scope: authorized scope is insufficient')
      }

      const { user } = accessToken

      const scope = await validateScope(user, client, requestedScope)
      if (!scope) throw new InvalidScopeError('Invalid scope: Requested scope is invalid')

      const authorizationCode = await generateAuthorizationCode(client, user, scope)

      const code = await saveAuthorizationCode({ authorizationCode, expiresAt, redirectUri, scope }, client, user)

      const redirectUriWithCode = url.parse(redirectUri, true)
      redirectUriWithCode.query.code = code.authorizationCode
      redirectUriWithCode.search = null

      return { redirectUri: redirectUriWithCode }

    } catch (e) {
      if (!(e instanceof OAuthError)) e = new ServerError(e)

      const redirectUriWithError = url.parse(redirectUri, false) // https://nodejs.org/api/url.html#url_whatwg_api

      redirectUriWithError.query = { error: e.name }
      if (e.message) redirectUriWithError.query.error_description = e.message

      throw e // TODO: Here we want to throw and return a redirect (maybe wrap in ErrorWithRedirectUri)
      return { redirectUri: redirectUriWithError }
    }
  }

  async function token(credentials, grantType) {
    options = _.assign({
      accessTokenLifetime: 60 * 60,             // 1 hour.
      refreshTokenLifetime: 60 * 60 * 24 * 14,  // 2 weeks.
      allowExtendedTokenAttributes: false,
      requireClientAuthentication: {}           // defaults to true for all grant types
    }, this.options, options);


    if (!credentials.clientId)
      throw new InvalidRequestError('Missing parameter: `client_id`');

    if (this.isClientAuthenticationRequired(grantType) && !credentials.clientSecret)
      throw new InvalidRequestError('Missing parameter: `client_secret`');

    if (!is.vschar(credentials.clientId))
      throw new InvalidRequestError('Invalid parameter: `client_id`');

    if (credentials.clientSecret && !is.vschar(credentials.clientSecret))
      throw new InvalidRequestError('Invalid parameter: `client_secret`');

    const client = await getClient(credentials.clientId, credentials.clientSecret)
    if (!client)
      throw new InvalidClientError('Invalid client: client is invalid');

    if (!client.grants)
      throw new ServerError('Server error: missing client `grants`');

    if (!(client.grants instanceof Array))
      throw new ServerError('Server error: `grants` must be an array');

  return promisify(this.model.getClient, 2).call(this.model, credentials.clientId, credentials.clientSecret)
    .then(function(client) {


      return client;
    })
    .catch(function(e) {

    });

    return Promise.bind(this)
    .then(function(client) {
      return this.handleGrantType(request, client);
    })
    .tap(function(data) {
      var model = new TokenModel(data, {allowExtendedTokenAttributes: this.allowExtendedTokenAttributes});
      var tokenType = this.getTokenType(model);

      this.updateSuccessResponse(response, tokenType);
    }).catch(function(e) {
      if (!(e instanceof OAuthError)) {
        e = new ServerError(e);
      }

      this.updateErrorResponse(response, e);

      throw e;
    });
  };
  }
}
