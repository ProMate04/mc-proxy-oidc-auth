package net.wafflecat.velocityOidcAuth.oidc;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.URI;
import java.util.List;

/**
 * Thin wrapper around the Nimbus OAuth2/OIDC SDK covering exactly the flow
 * this plugin needs: authorization code + PKCE, then ID token validation.
 */

public final class OidcClient {

    private final PluginConfig config;
    private final Logger logger;
    private final OIDCProviderMetadata metadata;
    private final ClientID clientId;
    private final Secret clientSecret;
    private final IDTokenValidator idTokenValidator;

    public OidcClient(VelocityOidcAuthPlugin plugin) throws IOException, com.nimbusds.oauth2.sdk.GeneralException {
        this.config = plugin.getConfig();
        this.logger = plugin.getLogger();
        this.clientId = new ClientID(config.clientId());
        this.clientSecret = config.clientSecret().isBlank() ? null : new Secret(config.clientSecret());

        Issuer issuer = new Issuer(config.issuer());
        this.metadata = OIDCProviderMetadata.resolve(issuer);

        List<JWSAlgorithm> supported = metadata.getIDTokenJWSAlgs();
        JWSAlgorithm alg = (supported != null && !supported.isEmpty()) ? supported.get(0) : JWSAlgorithm.RS256;

        this.idTokenValidator = new IDTokenValidator(
                metadata.getIssuer(),
                clientId,
                alg,
                metadata.getJWKSetURI().toURL()
        );

        logger.info("Resolved OIDC provider metadata for issuer {} (authorization_endpoint={}, token_endpoint={})",
                issuer.getValue(), metadata.getAuthorizationEndpointURI(), metadata.getTokenEndpointURI());
    }

     // Builds the URL the player's browser should be sent to, and the PKCE
     // code verifier that must be supplied again during token exchange.

    public AuthorizationRequestResult buildAuthorizationRequest(State state) {
        CodeVerifier codeVerifier = new CodeVerifier();

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                ResponseType.CODE,
                new Scope(config.scopes().toArray(new String[0])),
                clientId,
                URI.create(config.redirectUri().toString()))
                .endpointURI(metadata.getAuthorizationEndpointURI())
                .state(state)
                .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
                .build();

        return new AuthorizationRequestResult(request.toURI(), codeVerifier);
    }

     // Exchanges an authorization code for tokens and validates the ID token.
     // return the validated claim set from the ID token.
    public IDTokenClaimsSet exchangeAndValidate(String code, String codeVerifierValue) throws Exception {
        AuthorizationCodeGrant grant = new AuthorizationCodeGrant(
                new AuthorizationCode(code),
                URI.create(config.redirectUri().toString()),
                new CodeVerifier(codeVerifierValue));

        TokenRequest tokenRequest;
        if (clientSecret != null) {
            ClientAuthentication clientAuth = new ClientSecretBasic(clientId, clientSecret);
            tokenRequest = new TokenRequest(metadata.getTokenEndpointURI(), clientAuth, grant);
        } else {
            tokenRequest = new TokenRequest(metadata.getTokenEndpointURI(), clientId, grant);
        }

        HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            throw new IOException("Token endpoint returned an error: " + errorResponse.getErrorObject());
        }

        OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
        OIDCTokens tokens = successResponse.getOIDCTokens();
        JWT idToken = tokens.getIDToken();

        if (idToken == null) {
            throw new IOException("Token response did not include an ID token - "
                    + "make sure the 'openid' scope is requested and granted.");
        }

        // Validates issuer, audience, signature (via the provider's published
        // JWKS), and expiry/issued-at.
        return idTokenValidator.validate(idToken, null);
    }

    public String usernameClaim() {
        return config.usernameClaim();
    }
    public String UUIDClaim() {
        return config.UUIDClaim();
    }

    public static final class AuthorizationRequestResult {
        private final URI authorizationUri;
        private final CodeVerifier codeVerifier;

        AuthorizationRequestResult(URI authorizationUri, CodeVerifier codeVerifier) {
            this.authorizationUri = authorizationUri;
            this.codeVerifier = codeVerifier;
        }

        public URI authorizationUri() {
            return authorizationUri;
        }

        public CodeVerifier codeVerifier() {
            return codeVerifier;
        }
    }
}
