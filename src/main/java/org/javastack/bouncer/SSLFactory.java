package org.javastack.bouncer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;

public class SSLFactory {
	private final static char[] DEFAULT_PWD = "changeit".toCharArray();
	private final KeyStore ks;
	private final SSLContext ctx;
	private final CipherSuites cipherSuites;
	private final boolean needClientCert;

	public SSLFactory(final CipherSuites cipherSuites, final String priCert, final String priKey)
			throws IOException, GeneralSecurityException {
		this(cipherSuites, priCert, priKey, null);
	}

	public SSLFactory(final CipherSuites cipherSuites, final String priCert, final String priKey,
			final String pubCert) throws IOException, GeneralSecurityException {
		this.cipherSuites = cipherSuites;
		this.ks = initKeyStore(loadX509(priCert), loadPriKey(priKey), loadX509(pubCert));
		this.ctx = initSSLContext(ks);
		this.needClientCert = ((pubCert != null) && !pubCert.isEmpty());
	}

	public SSLServerSocket createSSLServerSocket() throws IOException {
		SSLServerSocketFactory factory = ctx.getServerSocketFactory();
		SSLServerSocket listen = (SSLServerSocket) factory.createServerSocket();
		listen.setEnabledProtocols(cipherSuites.getProtocols());
		listen.setEnabledCipherSuites(cipherSuites.getServerCipherSuites());
		listen.setNeedClientAuth(needClientCert); // Force Request Client Certificate
		return listen;
	}

	public SSLSocket createSSLSocket() throws IOException {
		SSLSocketFactory factory = ctx.getSocketFactory();
		SSLSocket sock = (SSLSocket) factory.createSocket();
		sock.setEnabledProtocols(cipherSuites.getProtocols());
		sock.setEnabledCipherSuites(cipherSuites.getClientCipherSuites());
		return sock;
	}

	public CipherSuites getCipherSuites() {
		return cipherSuites;
	}

	public static PrivateKey loadPriKey(final String fileName) throws IOException, GeneralSecurityException {
		PrivateKey key = null;
		InputStream is = null;
		try {
			is = fileName.getClass().getResourceAsStream("/" + fileName);
			final BufferedReader br = new BufferedReader(new InputStreamReader(is));
			final StringBuilder builder = new StringBuilder();
			boolean inKey = false;
			for (String line = br.readLine(); line != null; line = br.readLine()) {
				if (!inKey) {
					if (line.startsWith("-----BEGIN ") && line.endsWith(" PRIVATE KEY-----")) {
						inKey = true;
					}
					continue;
				} else {
					if (line.startsWith("-----END ") && line.endsWith(" PRIVATE KEY-----")) {
						inKey = false;
						break;
					}
					builder.append(line);
				}
			}
			final byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
			final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
			final KeyFactory kf = KeyFactory.getInstance("RSA");
			key = kf.generatePrivate(keySpec);
		} finally {
			IOHelper.closeSilent(is);
		}
		return key;
	}

	public static X509Certificate loadX509(final String fileName) throws GeneralSecurityException {
		if (fileName == null) {
			return null;
		}
		InputStream is = null;
		X509Certificate crt = null;
		try {
			final CertificateFactory cf = CertificateFactory.getInstance("X.509");
			is = fileName.getClass().getResourceAsStream("/" + fileName);
			crt = (X509Certificate) cf.generateCertificate(is);
		} finally {
			IOHelper.closeSilent(is);
		}
		return crt;
	}

	public static KeyStore initKeyStore(final X509Certificate priCert, final PrivateKey priKey,
			final X509Certificate pubCert) throws IOException, GeneralSecurityException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(null);
		if (pubCert != null) {
			ks.setCertificateEntry(pubCert.getSubjectX500Principal().getName(), pubCert);
		}
		ks.setKeyEntry("private", priKey, DEFAULT_PWD, new Certificate[] {
			priCert
		});
		return ks;
	}

	public static SSLContext initSSLContext(final KeyStore ks) throws GeneralSecurityException {
		final SSLContext ctx = SSLContext.getInstance("TLS");
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
				.getDefaultAlgorithm());
		kmf.init(ks, DEFAULT_PWD);
		tmf.init(ks);
		ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		return ctx;
	}

	public static String getSocketProtocol(final Socket sock) {
		if (sock instanceof SSLSocket) {
			final SSLSocket sslSock = (SSLSocket) sock;
			final SSLSession session = sslSock.getSession();
			final String id = SimpleHex.bytesAsHex(session.getId());
			return session.getProtocol() + ":" + session.getCipherSuite() + " ID=" + id;
		}
		return "";
	}
}
