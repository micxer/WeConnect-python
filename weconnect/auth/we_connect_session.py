import base64
import hashlib
import json
import logging
import secrets
import requests

from oauthlib.common import to_unicode
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import is_secure_transport

from requests.models import CaseInsensitiveDict
from weconnect.auth.openid_session import AccessType

from weconnect.auth.vw_web_session import VWWebSession
from weconnect.errors import AuthentificationError, RetrievalError, TemporaryAuthentificationError


LOG = logging.getLogger("weconnect")


class WeConnectSession(VWWebSession):
    def __init__(self, sessionuser, **kwargs):
        super(WeConnectSession, self).__init__(client_id='a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com',
                                               refresh_url='https://emea.bff.cariad.digital/auth/v1/idk/oidc/token',
                                               scope='openid profile badge cars vin',
                                               redirect_uri='weconnect://authenticated',
                                               state=None,
                                               sessionuser=sessionuser,
                                               **kwargs)

        # PKCE code verifier, generated per authorization request (see authorizationUrl)
        self.codeVerifier = None

        self.headers = CaseInsensitiveDict({
            'accept': '*/*',
            'content-type': 'application/json',
            'content-version': '1',
            'x-newrelic-id': 'VgAEWV9QDRAEXFlRAAYPUA==',
            'user-agent': 'Volkswagen/3.51.1-android/14',
            'accept-language': 'de-de',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'x-android-package-name': 'com.volkswagen.weconnect'
        })

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        access_type=AccessType.ACCESS,
        token=None,
        timeout=None,
        **kwargs
    ):
        """Intercept all requests and add weconnect-trace-id header."""

        import secrets
        traceId = secrets.token_hex(16)
        weConnectTraceId = (traceId[:8] + '-' + traceId[8:12] + '-' + traceId[12:16] + '-' + traceId[16:20] + '-' + traceId[20:]).upper()
        headers = headers or {}
        headers['weconnect-trace-id'] = weConnectTraceId

        return super(WeConnectSession, self).request(
            method, url, headers=headers, data=data, withhold_token=withhold_token, access_type=access_type, token=token, timeout=timeout, **kwargs
        )

    def login(self):
        super(WeConnectSession, self).login()
        authorizationUrl = self.authorizationUrl(url='https://identity.vwgroup.io/oidc/v1/authorize')
        response = self.doWebAuth(authorizationUrl)
        self.fetchTokens('https://emea.bff.cariad.digital/auth/v1/idk/oidc/token',
                         authorization_response=response
                         )

    def refresh(self):
        self.refreshTokens(
            'https://emea.bff.cariad.digital/auth/v1/idk/oidc/token',
        )

    def authorizationUrl(self, url, state=None, **kwargs):
        # The WeConnect SSO endpoints (/user-login/v1/authorize and
        # /user-login/login/v1) no longer work. Authenticate directly against the
        # OIDC authorize endpoint using the standard authorization_code + PKCE flow
        # and exchange the code at the cariad BFF OIDC token endpoint.
        self.codeVerifier = secrets.token_urlsafe(64)
        codeChallenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.codeVerifier.encode('ascii')).digest()
        ).decode('ascii').rstrip('=')

        return super(WeConnectSession, self).authorizationUrl(
            url, state=state, code_challenge=codeChallenge, code_challenge_method='S256', **kwargs
        )

    def clearTokens(self) -> None:
        """
        Clear all stored tokens to force a fresh login.
        
        This method is useful when the server requests new authorization
        and we need to clear invalid/expired tokens.
        """
        LOG.info("Clearing all stored tokens")
        self.token = None
        LOG.debug("All tokens cleared successfully")

    def fetchTokens(
        self,
        token_url,
        authorization_response=None,
        **kwargs
    ):
        self.parseFromFragment(authorization_response)

        if 'code' in self.token:
            # Exchange the authorization code for tokens at the OIDC token endpoint
            # using the standard authorization_code grant with the PKCE code verifier.
            body = {
                'grant_type': 'authorization_code',
                'code': self.token['code'],
                'code_verifier': self.codeVerifier,
                'redirect_uri': self.redirect_uri,
                'client_id': self.client_id,
            }

            loginHeadersForm: CaseInsensitiveDict = self.headers
            loginHeadersForm['accept'] = 'application/json'
            loginHeadersForm['content-type'] = 'application/x-www-form-urlencoded'

            tokenResponse = self.post(token_url, headers=loginHeadersForm, data=body, allow_redirects=False, access_type=AccessType.NONE)
            if tokenResponse.status_code != requests.codes['ok']:
                raise TemporaryAuthentificationError(f'Token could not be fetched due to temporary WeConnect failure: {tokenResponse.status_code}')
            token = self.parseFromBody(tokenResponse.text)

            # Ensure the token is properly stored in the session
            if token is not None:
                self.token = token  # Explicitly store the token
                LOG.debug(f"Successfully fetched tokens. Access token expires in: {token.get('expires_in', 'unknown')} seconds")
                LOG.debug(f"Refresh token available: {'refresh_token' in token}")
                # Verify critical tokens are present
                if not all(key in token for key in ('access_token', 'id_token', 'refresh_token')):
                    LOG.warning("Some expected tokens are missing from the response")
            else:
                LOG.error("Token parsing returned None")

            return token
        else:
            LOG.error("Authorization response missing authorization code")
            return None

    def parseFromBody(self, token_response, state=None):
        try:
            token = json.loads(token_response)
        except json.decoder.JSONDecodeError:
            raise TemporaryAuthentificationError('Token could not be refreshed due to temporary WeConnect failure: json could not be decoded')
        if 'accessToken' in token:
            token['access_token'] = token.pop('accessToken')
        if 'idToken' in token:
            token['id_token'] = token.pop('idToken')
        if 'refreshToken' in token:
            token['refresh_token'] = token.pop('refreshToken')
        fixedTokenresponse = to_unicode(json.dumps(token)).encode("utf-8")
        parsedToken = super(WeConnectSession, self).parseFromBody(token_response=fixedTokenresponse, state=state)
        # Ensure the token is stored in the session object
        self.token = parsedToken
        return parsedToken

    def refreshTokens(
        self,
        token_url,
        refresh_token=None,
        auth=None,
        timeout=None,
        headers=None,
        verify=True,
        proxies=None,
        **kwargs
    ):
        LOG.info('Refreshing tokens')
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        refresh_token = refresh_token or self.refreshToken

        if headers is None:
            headers = self.headers

        # First try to get from the current token property, then fall back to stored token
        if refresh_token is None:
            refresh_token = self.refreshToken
            # If still None, try to get from the token dict directly
            if refresh_token is None and self.token is not None:
                refresh_token = self.token.get('refresh_token')

        if not refresh_token:
            raise AuthentificationError('No refresh token available. Please log in again.')

        # Create headers matching the examples format
        tHeaders = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Volkswagen/3.51.1-android/14",
            "x-android-package-name": "com.volkswagen.weconnect",
        }

        # Create form data body matching the examples format
        body = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }

        # Request new tokens using POST with form data
        tokenResponse = self.post(
            token_url,
            data=body,
            headers=tHeaders,
            timeout=timeout,
            verify=verify,
            proxies=proxies,
        )
        if tokenResponse.status_code == requests.codes['unauthorized']:
            LOG.error('Token refresh failed with 401 - server requests new authorization. Refresh token may be expired or invalid.')
            raise AuthentificationError('Refreshing tokens failed: Server requests new authorization. Please log in again.')
        elif tokenResponse.status_code in (requests.codes['internal_server_error'], requests.codes['service_unavailable'], requests.codes['gateway_timeout']):
            raise TemporaryAuthentificationError(f'Token could not be refreshed due to temporary WeConnect failure: {tokenResponse.status_code}')
        elif tokenResponse.status_code == requests.codes['ok']:
            newToken = self.parseFromBody(tokenResponse.text)
            if newToken is not None and "refresh_token" not in newToken:
                LOG.debug("No new refresh token given. Re-using old.")
                self.token["refresh_token"] = refresh_token
                # Update the token property as well
                self.token = newToken
            return newToken
        else:
            raise RetrievalError(f'Status Code from WeConnect while refreshing tokens was: {tokenResponse.status_code}')
