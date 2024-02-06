import lombok.SneakyThrows;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

public class MtlsClientFactory {
    private static final String DEFAULT_KEYSTORE_PASSWORD = "password";

    String secretKey; // Secret key associated to the client's certificate.
    String clientCertificate;
    String trustedCaCertificate;

    public MtlsClientFactory(
            String secretKey,
            String clientCertificate,
            String trustedCaCertificate
    ) {
        this.secretKey = secretKey;
        this.clientCertificate = clientCertificate;
        this.trustedCaCertificate = trustedCaCertificate;
    }

    @SneakyThrows
    public HttpClient createMtlsClient() {
        return HttpClients.custom()
                .setSSLContext(this.getSslContext())
                .setSSLHostnameVerifier(new DefaultHostnameVerifier())
                .build();
    }

    @SneakyThrows
    private SSLContext getSslContext() {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                this.getClientKeyManagers(),
                this.getTrustManagers(),
                null
        );
        return sslContext;
    }

    @SneakyThrows
    private KeyManager[] getClientKeyManagers() {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(this.getClientKeyStore(), DEFAULT_KEYSTORE_PASSWORD.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    @SneakyThrows
    private KeyStore getClientKeyStore() {
        KeyStore clientKeyStore = KeyStore.getInstance("jks");

        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry(
                "client_store",
                this.getPrivateKey(),
                DEFAULT_KEYSTORE_PASSWORD.toCharArray(),
                this.getClientCertificateChain()
        );

        return clientKeyStore;
    }

    @SneakyThrows
    private Key getPrivateKey() {
        String privateString = this.secretKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(privateString);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    @SneakyThrows
    private Certificate[] getClientCertificateChain() {
        byte[] data = this.clientCertificate.getBytes(Charset.defaultCharset());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certificateChain = certificateFactory.generateCertificates(
                new ByteArrayInputStream(data)
        );

        return certificateChain.toArray(new Certificate[0]);
    }

    @SneakyThrows
    private TrustManager[] getTrustManagers() {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(this.getTrustStore());
        return tmf.getTrustManagers();
    }

    @SneakyThrows
    private KeyStore getTrustStore() {

        KeyStore trustStore = KeyStore.getInstance("jks");

        trustStore.load(null, null);
        trustStore.setCertificateEntry(
                "trusted_cas",
                this.getCaCertificate()
        );

        return trustStore;
    }

    @SneakyThrows
    private Certificate getCaCertificate() {
        byte[] data = this.trustedCaCertificate.getBytes(Charset.defaultCharset());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return certificateFactory.generateCertificate(new ByteArrayInputStream(data));
    }

    @SneakyThrows
    public static void main(String[] args) {


        // Build the MTLS client
        String privateKeyPath = "/Users/luikyraidiam/Repositories/mtls/src/main/resources/secret.key";
        String publicKeyPath = "/Users/luikyraidiam/Repositories/mtls/src/main/resources/certificate.pem";
        String serverCertificatePath = "/Users/luikyraidiam/Repositories/mtls/src/main/resources/raidiam.cer";
        String clientSecretKey = new String(
                Files.readAllBytes(Path.of(privateKeyPath)),
                Charset.defaultCharset()
        );
        String clientCertificate = new String(
                Files.readAllBytes(Path.of(publicKeyPath)),
                Charset.defaultCharset()
        );
        String trustedCaCertificate = new String(
                Files.readAllBytes(Path.of(serverCertificatePath)),
                Charset.defaultCharset()
        );
        MtlsClientFactory mtlsClientFactory = new MtlsClientFactory(
                clientSecretKey,
                clientCertificate,
                trustedCaCertificate
        );

        // Build the request
        HttpPost httpPost = new HttpPost("https://matls-auth.sandbox.raidiam.io/token");
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("client_id", "ddac503c-acf9-4ac2-844d-d3b8cef5c72e"));
        params.add(new BasicNameValuePair("scope", "directory:software"));
        params.add(new BasicNameValuePair("grant_type", "client_credentials"));
        httpPost.setEntity(new UrlEncodedFormEntity(params));

        // Call protected endpoint
        CloseableHttpResponse response;
        try (CloseableHttpClient client = (CloseableHttpClient) mtlsClientFactory.createMtlsClient()) {
            response = client.execute(httpPost);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw e;
        }
        System.out.println(EntityUtils.toString(response.getEntity()));

    }
}
