import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.HttpClients;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;

public class MtlsClientFactory {
    private static final String DEFAULT_KEYSTORE_PASSWORD = "password";

    String privateKeyPath;
    String publicKeyPath;
    String serverCertificatePath;

    public MtlsClientFactory(
            String privateKeyPath,
            String publicKeyPath,
            String serverCertificatePath
    ) {
        this.privateKeyPath = privateKeyPath;
        this.publicKeyPath = publicKeyPath;
        this.serverCertificatePath = serverCertificatePath;
    }

    public HttpClient createMtlsClient() throws NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
        return HttpClients.custom()
                .setSSLContext(this.getSslContext())
                .setSSLHostnameVerifier(new DefaultHostnameVerifier())
                .build();
    }

    private SSLContext getSslContext() throws NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                this.getClientKeyManagers(),
                this.getTrustManagers(),
                null
        );
        return sslContext;
    }

    private KeyManager[] getClientKeyManagers() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(this.getClientKeyStore(), DEFAULT_KEYSTORE_PASSWORD.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    private KeyStore getClientKeyStore() {
        KeyStore clientKeyStore = KeyStore.getInstance("jks");
        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry(
                "test",
                this.getPrivateKey(),
                DEFAULT_KEYSTORE_PASSWORD.toCharArray(),
                this.getClientCertificateChain()
        );
    }

    private Key getPrivateKey() {
        byte[] privateData = Files.readAllBytes(Path.of(privateKeyPath));
        String privateString = new String(privateData, Charset.defaultCharset())
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(privateString);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private TrustManager[] getTrustManagers() {
        TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(this.getTrustStore());
        return tmf.getTrustManagers();
    }

    private KeyStore getTrustStore() {
        InputStream is = new FileInputStream(this.serverCertificatePath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(is);
        KeyStore trustStore = KeyStore.getInstance("jks");
        trustStore.load(null, null);
        trustStore.setCertificateEntry(
                "server",
                caCert
        );
    }

    private Certificate[] getClientCertificateChain() {
        return this.getCertificateChain(this.publicKeyPath);
    }

    private Certificate[] getServerCertificateChain() {
        return this.getCertificateChain(this.serverCertificatePath);
    }

    private Certificate[] getCertificateChain(String certificatePath) {
        byte[] data = Files.readAllBytes(Path.of(certificatePath));
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final Collection<? extends Certificate> chain = certificateFactory.generateCertificates(
                new ByteArrayInputStream(data));
        return chain.toArray(new Certificate[0]);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, InvalidKeySpecException, UnrecoverableKeyException, KeyManagementException {

        String privateKeyPath = "/path/to/generated/client.key.pkcs8";
        String publicKeyPath = "/path/to/generated/client.crt";
        String serverCertificatePath = "/path/to/generated/server.crt";
        byte[] privateData = Files.readAllBytes(Path.of(privateKeyPath));
        byte[] publicData = Files.readAllBytes(Path.of(publicKeyPath));
        byte[] serverCertificateData = Files.readAllBytes(Path.of(serverCertificatePath));

        String privateString = new String(privateData, Charset.defaultCharset())
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(privateString);
        Key key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));

        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final Collection<? extends Certificate> chain = certificateFactory.generateCertificates(
                new ByteArrayInputStream(publicData));

        final Collection<? extends Certificate> serverChain = certificateFactory.generateCertificates(
                new ByteArrayInputStream(serverCertificateData));
        certificateFactory.generateCertificate()

        KeyStore clientKeyStore = KeyStore.getInstance("jks");
        char[] pwdChars = "test".toCharArray();
        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry("test", key, pwdChars, chain.toArray(new Certificate[0]));
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(clientKeyStore, pwdChars);

        KeyStore trustStore = KeyStore.getInstance("jks");
        pwdChars = "test".toCharArray();
        trustStore.load(null, null);
        trustStore.setKeyEntry("test", key, pwdChars, chain.toArray(new Certificate[0]));
        trustStore.setCertificateEntry("bla", );
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm);
        trustManagerFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory.getTrustManagers(),
                null
        );

        HttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLHostnameVerifier(new DefaultHostnameVerifier())
                .build();

        HttpGet request = new HttpGet("https://localhost:8443/api/hello");
        HttpResponse response = httpClient.execute(request);
    }
}
