package br.com.inkinvite.infrastructure.security;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class KeycloakProvider {

    @Inject
    @ConfigProperty(name = "URL_ONLY")
    private String serverURL;

    @Inject
    @ConfigProperty(name = "REALM_NAME")
    private String realmName;

    @Inject
    @ConfigProperty(name = "CLIENT_ID")
    private String clientId;

    @Inject
    @ConfigProperty(name = "CLIENT_SECRET")
    private String clientSecret;

    @Inject
    @ConfigProperty(name = "KC_USERNAME")
    private String adminLogin;

    @Inject
    @ConfigProperty(name = "KC_PASSWORD")
    private String adminSenha;

    private SSLContext createSSLContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());
        return sslContext;
    }

    private Keycloak buildKeycloakClient(String username, String password, String grantType) {
        try {
            SSLContext sslContext = createSSLContext();

            KeycloakBuilder builder = KeycloakBuilder.builder()
                .resteasyClient(ResteasyClientBuilder.newBuilder()
                    .sslContext(sslContext)
                    .hostnameVerifier((hostname, session) -> true)
                    .build())
                .serverUrl(serverURL)
                .realm(realmName)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(grantType);

            if (username != null && password != null) {
                builder.username(username).password(password);
            }

            return builder.build();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public Keycloak obterClientKeycloak() {
        return buildKeycloakClient(null, null, OAuth2Constants.CLIENT_CREDENTIALS);
    }

    public Keycloak obterClientKeycloakPorLogin(String login, String senha) {
        return buildKeycloakClient(login, senha, OAuth2Constants.PASSWORD);
    }

    public Keycloak obterValidacaoAdmin() {
        return buildKeycloakClient(adminLogin, adminSenha, OAuth2Constants.PASSWORD);
    }

    public String getRealmName() {
        return realmName;
    }
}
