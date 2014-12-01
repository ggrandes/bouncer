package org.javastack.bouncer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

public class CipherSuites {
	private String[] protos = null;
	private String[] clientSuites = null;
	private String[] serverSuites = null;

	public CipherSuites() throws NoSuchAlgorithmException, IOException {
		init();
	}

	private void load(final List<String> clientSuites, final List<String> serverSuites) throws IOException {
		BufferedReader in = null;
		try {
			in = new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream(
					Constants.SUITES_FILE)));
			String line = null;
			while ((line = in.readLine()) != null) {
				line = line.trim();
				if (line.charAt(0) == '#')
					continue;
				final String[] tok = line.split("=", 2);
				final String algorith = tok[0].trim().toUpperCase();
				final String usage = tok[1].trim().toUpperCase();
				if (usage.indexOf('C') != -1) {
					if (!clientSuites.contains(algorith))
						clientSuites.add(algorith);
				}
				if (usage.indexOf('S') != -1) {
					if (!serverSuites.contains(algorith))
						serverSuites.add(algorith);
				}
			}
		} finally {
			try {
				if (in != null)
					in.close();
			} catch (Exception ign) {
			}
		}
	}

	private void filterSupportedSSLParameters(final List<String> protos, final List<String> clientSuites,
			final List<String> serverSuites) throws NoSuchAlgorithmException {
		final SSLContext ctx = SSLContext.getDefault();
		final SSLParameters sslParams = ctx.getSupportedSSLParameters();
		protos.retainAll(Arrays.asList(sslParams.getProtocols()));
		clientSuites.retainAll(Arrays.asList(sslParams.getCipherSuites()));
		serverSuites.retainAll(Arrays.asList(sslParams.getCipherSuites()));
	}

	private void init() throws NoSuchAlgorithmException, IOException {
		final List<String> protos = new ArrayList<String>();
		final List<String> clientSuites = new ArrayList<String>();
		final List<String> serverSuites = new ArrayList<String>();
		protos.add("TLSv1.2");
		protos.add("TLSv1.1");
		protos.add("TLSv1");
		load(clientSuites, serverSuites);
		filterSupportedSSLParameters(protos, clientSuites, serverSuites);
		this.protos = protos.toArray(new String[protos.size()]);
		this.clientSuites = clientSuites.toArray(new String[clientSuites.size()]);
		this.serverSuites = serverSuites.toArray(new String[serverSuites.size()]);
	}

	public void setupClientCipherSuites(final SSLParameters sslParams) {
		sslParams.setProtocols(protos);
		sslParams.setCipherSuites(clientSuites);
	}

	public void setupServerCipherSuites(final SSLParameters sslParams) {
		sslParams.setProtocols(protos);
		sslParams.setCipherSuites(serverSuites);
	}

	public String[] getProtocols() {
		return protos.clone();
	}

	public String[] getClientCipherSuites() {
		return clientSuites.clone();
	}

	public String[] getServerCipherSuites() {
		return serverSuites.clone();
	}

	public static void main(final String[] args) throws Throwable {
		try {
			final String bcName = "org.bouncycastle.jce.provider.BouncyCastleProvider";
			Security.addProvider((Provider) Class.forName(bcName).newInstance());
		} catch (Throwable t) {
			Log.warn("Unable to register BouncyCastleProvider: " + t.toString());
		}
		final SSLContext ctx = SSLContext.getDefault();
		final SSLParameters sslParams = ctx.getDefaultSSLParameters();
		final CipherSuites suites = new CipherSuites();
		System.out.println("### CLIENT ###");
		suites.setupClientCipherSuites(sslParams);
		System.out.println(Arrays.asList(sslParams.getProtocols()));
		System.out.println(Arrays.asList(sslParams.getCipherSuites()));
		System.out.println("### SERVER ###");
		suites.setupServerCipherSuites(sslParams);
		System.out.println(Arrays.asList(sslParams.getProtocols()));
		System.out.println(Arrays.asList(sslParams.getCipherSuites()));
	}
}
