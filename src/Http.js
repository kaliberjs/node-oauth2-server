module.exports = {
  authenticate: {
    getTokenFromRequest,
    addAcceptedScopesHeaderToResponse,
    addAuthorizedScopesHeaderToResponse,
    handleErrorResponse,
  },
  authorize: {
    checkRequestAllowed,
    getClientIdFromRequest,
    getRedirectUriFromRequest,
    handleErrorResponse,
    getTokenFromRequest,
    addAcceptedScopesHeaderToResponse,
    addAuthorizedScopesHeaderToResponse,
    getScopeFromRequest,
    getStateFromRequest,
    checkResponseType,
    handleResponse,
  },
  token: {
    checkRequestValid,
    getCredentialsFromRequest,
    getGrantTypeFromRequest,
    handleErrorResponse,
  }
}

function getGrantTypeFromRequest(request) {
  const grantType = request.body.grant_type

  return grantType
}

function getCredentialsFromRequest(request) {
  /**
   * Get client credentials.
   *
   * The client credentials may be sent using the HTTP Basic authentication scheme or, alternatively,
   * the `client_id` and `client_secret` can be embedded in the body.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
   */

   const credentials = auth(request)

   if (credentials)
     return { clientId: credentials.name, clientSecret: credentials.pass }

   if (request.body.client_id && request.body.client_secret)
     return { clientId: request.body.client_id, clientSecret: request.body.client_secret }

   throw new InvalidClientError('Invalid client: cannot retrieve client credentials')
}

async function checkRequestValid(request) {
  if (request.method !== 'POST')
    throw new InvalidRequestError('Invalid request: method must be POST')
  if (!request.is('application/x-www-form-urlencoded'))
    throw new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded')
}

function handleResponse(response, redirectUri, state) {
  redirectUri.query = redirectUri.query || {}

  if (state) redirectUri.query.state = state

  response.redirect(url.format(redirectUri))
}

function checkResponseType(request) {
  const responseType = request.body.response_type || request.query.response_type

  if (!responseType)
    throw new InvalidRequestError('Missing parameter: `response_type`')

  if (!['code'].includes(responseType))
    throw new UnsupportedResponseTypeError('Unsupported response type: `response_type` is not supported')
}

function getStateFromRequest(request, { allowEmptyState = false }) {
  var state = request.body.state || request.query.state

  if (!allowEmptyState && !state)
    throw new InvalidRequestError('Missing parameter: `state`')
  if (!is.vschar(state))
    throw new InvalidRequestError('Invalid parameter: `state`')

  return state
}

function getScopeFromRequest(request) {
  const scope = request.body.scope || request.query.scope

  if (!is.nqschar(scope)) throw new InvalidScopeError('Invalid parameter: `scope`')

  return scope
}

function getClientIdFromRequest(request) {
  const clientId = request.body.client_id || request.query.client_id

  if (!clientId) throw new InvalidRequestError('Missing parameter: `client_id`')
  if (!is.vschar(clientId)) throw new InvalidRequestError('Invalid parameter: `client_id`')

  return clientId
}

function getRedirectUriFromRequest(request) {
  const redirectUri = request.body.redirect_uri || request.query.redirect_uri

  if (redirectUri && !is.uri(redirectUri))
    throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI')

  return redirectUri
}

async function checkRequestAllowed(request) {
  if (request.query.allowed === 'false')
    throw new AccessDeniedError('Access denied: user denied access to application')
}

function handleErrorResponse(request, response, e) {
  /**
   * Include the "WWW-Authenticate" response header field if the client
   * lacks any authentication information.
   *
   * @see https://tools.ietf.org/html/rfc6750#section-3.1
   */
  if (e instanceof UnauthorizedRequestError)
    response.set('WWW-Authenticate', 'Bearer realm="Service"')

  if ((e instanceof InvalidClientError) && request.get('authorization')) {
    response.set('WWW-Authenticate', 'Basic realm="Service"');

    throw new InvalidClientError(e, { code: 401 });
  }

  if (!(e instanceof OAuthError)) throw new ServerError(e)

  throw e
}

function addAcceptedScopesHeaderToResponse(response, scope) {
  response.set('X-Accepted-OAuth-Scopes', scope)
}

function addAuthorizedScopesHeaderToResponse(response, accessToken) {
  response.set('X-OAuth-Scopes', accessToken.scope)
}

function getTokenFromRequest(request, { allowBearerTokensInQueryString = false }) {
  const headerToken = request.get('Authorization')
  const queryToken = request.query.access_token
  const bodyToken = request.body.access_token

  const [hasHeaderToken, hasQueryToken, hasBodyToken] =
    [Boolean(headerToken), Boolean(queryToken), Boolean(bodyToken)]

  if (hasHeaderToken + hasQueryToken + hasBodyToken > 1)
    throw new InvalidRequestError('Invalid request: only one authentication method is allowed')

  if (hasHeaderToken) {
    /**
     * Get the token from the request header.
     *
     * @see http://tools.ietf.org/html/rfc6750#section-2.1
     */
    const [, token] = headerToken.match(/Bearer\s(\S+)/) || []
    if (!token) throw new InvalidRequestError('Invalid request: malformed authorization header')
    return token
  }

  if (hasQueryToken) {
    /**
     * Get the token from the request query.
     *
     * "Don't pass bearer tokens in page URLs:  Bearer tokens SHOULD NOT be passed in page
     * URLs (for example, as query string parameters). Instead, bearer tokens SHOULD be
     * passed in HTTP message headers or message bodies for which confidentiality measures
     * are taken. Browsers, web servers, and other software may not adequately secure URLs
     * in the browser history, web server logs, and other data structures. If bearer tokens
     * are passed in page URLs, attackers might be able to steal them from the history data,
     * logs, or other unsecured locations."
     *
     * @see http://tools.ietf.org/html/rfc6750#section-2.3
     */

    if (!allowBearerTokensInQueryString)
      throw new InvalidRequestError('Invalid request: do not send bearer tokens in query URLs')

    return queryToken
  }

  if (hasBodyToken) {
    /**
     * Get the token from the request body.
     *
     * "The HTTP request method is one for which the request-body has defined semantics.
     * In particular, this means that the "GET" method MUST NOT be used."
     *
     * @see http://tools.ietf.org/html/rfc6750#section-2.2
     */

    if (request.method === 'GET')
      throw new InvalidRequestError('Invalid request: token may not be passed in the body when using the GET verb')

    if (!request.is('application/x-www-form-urlencoded'))
      throw new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded')

    return bodyToken
  }

  throw new UnauthorizedRequestError('Unauthorized request: no authentication given')
}
