/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.javastack.bouncer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.xml.bind.DatatypeConverter;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Generate RSA keys and X.509 self-signed certificates for SSL/TLS
 * 
 * @author Guillermo Grandes / guillermo.grandes[at]gmail.com
 */
@SuppressWarnings("restriction")
public class KeyGenerator {
	private static final String KEYPAIR_ALG = "RSA";
	private static final String SIGNATURE_ALG = "SHA256withRSA";

	public static void main(String[] args) throws Exception {
		final String iam = KeyGenerator.class.getName();
		if (args.length < 4) {
			System.out.println("java " + iam + " <bits> <days> <CommonName> <filename-without-extension>");
			System.out.println("");
			System.out.println("Example:");
			System.out.println("  java " + iam + " 2048 365 TestServer test");
			System.out.println("");
			System.out.println("* Output files are named <filename>.crt & <filename>.key");
			return;
		}
		int i = 0;
		final int bits = Integer.parseInt(args[i++]);
		final int days = Integer.parseInt(args[i++]);
		final String cn = args[i++];
		final String file = args[i++];
		//
		// Generate RSA Key
		final KeyPairGenerator kgAsym = KeyPairGenerator.getInstance(KEYPAIR_ALG);
		kgAsym.initialize(bits);
		final KeyPair kp = kgAsym.genKeyPair();
		File keyFile = new File(file + ".key");
		writeKey(new FileOutputStream(keyFile), kp.getPrivate());
		// Clear permissions
		keyFile.setExecutable(false, false);
		keyFile.setReadable(false, false);
		keyFile.setReadable(true);
		keyFile.setWritable(false, false);
		keyFile.setWritable(true);
		//
		// Generate & SelfSign X.509
		final X509Certificate crt = generateCertificate("CN=" + cn, kp, days, SIGNATURE_ALG);
		final File crtFile = new File(file + ".crt");
		writeCertificate(new FileOutputStream(crtFile), crt);
	}

	/**
	 * Create a self-signed X.509 Certificate
	 * 
	 * @param dn the X.509 Distinguished Name, eg "CN=Test"
	 * @param pair the KeyPair
	 * @param days how many days from now the Certificate is valid for
	 * @param algName algorithm name, eg SHA256withRSA
	 */
	static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algName)
			throws Exception {
		final PrivateKey privkey = pair.getPrivate();
		final X509CertInfo info = new X509CertInfo();
		final Date from = new Date();
		final Date to = new Date(from.getTime() + days * 86400000L);
		final CertificateValidity interval = new CertificateValidity(from, to);
		final int sn = (int) ((System.currentTimeMillis() / 1000) & 0xFFFFFFFF);
		final X500Name owner = new X500Name(dn);

		final AlgorithmId algo = AlgorithmId.get(algName);
		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
		info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
		info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
		info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

		// Extensions
		final CertificateExtensions ext = new CertificateExtensions();
		ext.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(Boolean.TRUE, true, 0)); // Critical|isCA|pathLen
		ext.set(SubjectKeyIdentifierExtension.NAME,
				new SubjectKeyIdentifierExtension(new KeyIdentifier(pair.getPublic()).getIdentifier()));
		ext.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(new KeyIdentifier(
				pair.getPublic()), null, null));
		// Extended Key Usage Extension
		final Vector<ObjectIdentifier> ekue = new Vector<ObjectIdentifier>();
		ekue.add(new ObjectIdentifier(new int[] {
				1, 3, 6, 1, 5, 5, 7, 3, 1
		})); // Server
		ekue.add(new ObjectIdentifier(new int[] {
				1, 3, 6, 1, 5, 5, 7, 3, 2
		})); // Client
		ext.set(ExtendedKeyUsageExtension.NAME, new ExtendedKeyUsageExtension(Boolean.FALSE, ekue));
		info.set(X509CertInfo.EXTENSIONS, ext);

		// Sign the X.509
		final X509CertImpl cert = new X509CertImpl(info);
		cert.sign(privkey, algo.getName());
		return cert;
	}

	static void writeBufferBase64(OutputStream out, byte[] bufIn) throws IOException {
		final byte[] buf = DatatypeConverter.printBase64Binary(bufIn).getBytes();
		final int BLOCK_SIZE = 64;
		for (int i = 0; i < buf.length; i += BLOCK_SIZE) {
			out.write(buf, i, Math.min(BLOCK_SIZE, buf.length - i));
			out.write('\r');
			out.write('\n');
		}
	}

	static void writeCertificate(OutputStream out, X509Certificate crt) throws Exception {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write("-----BEGIN CERTIFICATE-----\r\n".getBytes());
		writeBufferBase64(baos, crt.getEncoded());
		baos.write("-----END CERTIFICATE-----\r\n".getBytes());
		out.write(baos.toByteArray());
		out.flush();
		out.close();
		System.out.println(baos.toString());
	}

	static void writeKey(OutputStream out, PrivateKey pk) throws Exception {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write("-----BEGIN RSA PRIVATE KEY-----\r\n".getBytes());
		writeBufferBase64(baos, pk.getEncoded());
		baos.write("-----END RSA PRIVATE KEY-----\r\n".getBytes());
		out.write(baos.toByteArray());
		out.flush();
		out.close();
		System.out.println(baos.toString());
	}
}
