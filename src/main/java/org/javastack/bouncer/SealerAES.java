package org.javastack.bouncer;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SealerAES {
	private static final Charset UTF8 = Charset.forName("UTF-8");
	private static final int FLAG_REKEY = 0x01; // Rekey

	private final SecureRandom rnd = new SecureRandom();
	private final String cipherAlg;
	private final int cipherKeyBits;
	private final boolean wayAorB;
	private final byte[] ivEncoder;
	private final char[] secret;

	private SecretKeySpec encSecretCipher;
	private SecretKeySpec decSecretCipher;
	private SecretKeySpec encSecretMac;
	private SecretKeySpec decSecretMac;

	private Cipher enc;
	private Cipher dec;
	private Mac encMac;
	private Mac decMac;

	private int encSeq = 0;
	private int decSeq = 0;

	public SealerAES(final String key, final boolean wayAorB) {
		this(key, null, 0, wayAorB);
	}

	public SealerAES(final String key, final String cipherAlg, final int bits, final boolean wayAorB) {
		try {
			this.secret = key.toCharArray();
			this.cipherAlg = (cipherAlg != null ? cipherAlg : Constants.SEALER_CIPHER_ALG);
			this.cipherKeyBits = Math.max(bits, Constants.SEALER_CIPHER_MIN_KEY_BITS);
			this.wayAorB = wayAorB;
			this.enc = Cipher.getInstance(this.cipherAlg);
			this.dec = Cipher.getInstance(this.cipherAlg);
			this.ivEncoder = new byte[enc.getBlockSize()];
			//
			this.setSecret(this.secret, 0);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "@" + Integer.toHexString(hashCode());
	}

	public void reset() throws GeneralSecurityException {
		Log.info(this.toString() + " reset");
		encSeq = 0;
		decSeq = 0;
		setSecret(this.secret, 0);
	}

	private final void setSecret(final char[] key, final int seq) throws GeneralSecurityException {
		Log.info(this.toString() + " cipher=" + cipherAlg + " bits=" + cipherKeyBits);
		setSecretWayA(key, seq);
		setSecretWayB(key, seq);
	}

	private final void setSecret(final char[] key, final int seq, final boolean wayAorB)
			throws GeneralSecurityException {
		if (wayAorB) {
			setSecretWayA(key, seq);
		} else {
			setSecretWayB(key, seq);
		}
	}

	private final String getAlg(final String cipherAlg) {
		final int offset = cipherAlg.indexOf('/');
		if (offset > 0) {
			return cipherAlg.substring(0, offset);
		}
		return cipherAlg;
	}

	private final void setSecretWayA(final char[] key, final int seq) throws GeneralSecurityException {
		final int macBitLength = Mac.getInstance(Constants.SEALER_HMAC_ALG).getMacLength() * 8;
		final int saltSeq = miniHash(this.secret) ^ seq;
		final SecretKeySpec secretCipherA = key(key, "cipher-A", saltSeq, 5009, cipherKeyBits,
				getAlg(cipherAlg));
		final SecretKeySpec secretMacA = key(key, "hmac-A", saltSeq, 5011, macBitLength,
				Constants.SEALER_HMAC_ALG);
		if (wayAorB) {
			this.encSecretCipher = secretCipherA;
			this.encSecretMac = secretMacA;
			this.initEncMac();
		} else {
			this.decSecretCipher = secretCipherA;
			this.decSecretMac = secretMacA;
			this.initDecMac();
		}
	}

	private final void setSecretWayB(final char[] key, final int seq) throws GeneralSecurityException {
		final int macBitLength = Mac.getInstance(Constants.SEALER_HMAC_ALG).getMacLength() * 8;
		final int saltSeq = miniHash(this.secret) ^ seq;
		final SecretKeySpec secretCipherB = key(key, "cipher-B", saltSeq, 5021, cipherKeyBits,
				getAlg(cipherAlg));
		final SecretKeySpec secretMacB = key(key, "hmac-B", saltSeq, 5023, macBitLength,
				Constants.SEALER_HMAC_ALG);
		if (wayAorB) {
			this.decSecretCipher = secretCipherB;
			this.decSecretMac = secretMacB;
			this.initDecMac();
		} else {
			this.encSecretCipher = secretCipherB;
			this.encSecretMac = secretMacB;
			this.initEncMac();
		}
	}

	private final void initEncMac() throws NoSuchAlgorithmException, InvalidKeyException {
		final Mac encMac = Mac.getInstance(Constants.SEALER_HMAC_ALG);
		encMac.init(encSecretMac);
		this.encMac = encMac;
	}

	private final void initDecMac() throws NoSuchAlgorithmException, InvalidKeyException {
		final Mac decMac = Mac.getInstance(Constants.SEALER_HMAC_ALG);
		decMac.init(decSecretMac);
		this.decMac = decMac;
	}

	private final int genTS() {
		return (int) ((System.currentTimeMillis() / 1000) & Integer.MAX_VALUE);
	}

	private final int encSeq() {
		return (++encSeq & Integer.MAX_VALUE);
	}

	private final int decSeq() {
		return (++decSeq & Integer.MAX_VALUE);
	}

	static final SecretKeySpec key(final char[] secret, final String salt, final int saltSeq,
			final int iterationCount, final int keyLengthBits, final String alg)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		return new SecretKeySpec(hashPassword(secret, salt, saltSeq, iterationCount, keyLengthBits), alg);
	}

	static final int miniHash(final char[] in) {
		if (in == null)
			return 0;
		// One-at-a-Time hash (Bob Jenkins)
		int h = 0;
		for (int i = 0; i < in.length; i++) {
			h += in[i];
			h += (h << 10);
			h ^= (h >> 6);
		}
		h += (h << 3);
		h ^= (h >> 11);
		h += (h << 15);
		return h;
	}

	static final byte[] saltSeq(final String salt, final int seq) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance(Constants.SEALER_MD_ALG);
		md.update((byte) ((seq >> 24) & 0xFF));
		md.update((byte) ((seq >> 16) & 0xFF));
		md.update((byte) ((seq >> 8) & 0xFF));
		md.update((byte) ((seq >> 0) & 0xFF));
		return md.digest(salt.getBytes(UTF8));
	}

	static final byte[] hashPassword(final char[] value, final String salt, final int saltSeq,
			final int iterationCount, final int keyLengthBits) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		final PBEKeySpec spec = new PBEKeySpec(value, saltSeq(salt, saltSeq), iterationCount, keyLengthBits);
		final SecretKeyFactory key = SecretKeyFactory.getInstance(Constants.SEALER_PBKDF_ALG);
		return key.generateSecret(spec).getEncoded();
	}

	private final Cipher getCoder(final boolean generateIV) throws IOException, GeneralSecurityException {
		if (generateIV) {
			rnd.nextBytes(ivEncoder);
			enc.init(Cipher.ENCRYPT_MODE, encSecretCipher, new IvParameterSpec(ivEncoder));
		}
		return enc;
	}

	private final Cipher getDecoder(final byte[] iv) throws IOException, GeneralSecurityException {
		dec.init(Cipher.DECRYPT_MODE, decSecretCipher, new IvParameterSpec(iv));
		return dec;
	}

	public byte[] code(final byte[] buf, final int off, final int len) throws IOException,
			GeneralSecurityException {
		// { IV + { SEQ(4) + TS(4) + FLAGS(1) + [REKEY] + DATA(n) }CRYPT }HMAC
		final Cipher enc = getCoder(true);
		final int sendSeq = encSeq();
		final boolean reKey = ((sendSeq & Constants.SEALER_REKEY_PACKETS) == 1);
		final int outCipSize = 4 + 4 + 1 + len + (reKey ? (cipherKeyBits >>> 3) : 0);
		final byte[] out = new byte[enc.getBlockSize() + //
				enc.getOutputSize(outCipSize) + //
				encMac.getMacLength()];
		int outLen = 0;
		// IV
		System.arraycopy(ivEncoder, 0, out, 0, ivEncoder.length);
		outLen += ivEncoder.length;
		// SEQ(4)
		IOHelper.intToByteArray(sendSeq, out, outLen);
		outLen += enc.update(out, outLen, 4, out, outLen);
		// TimeStamp(4)
		final int sendTS = genTS();
		IOHelper.intToByteArray(sendTS, out, outLen);
		outLen += enc.update(out, outLen, 4, out, outLen);
		// FLAGS(1)
		out[outLen] = 0;
		if (reKey) {
			out[outLen] |= FLAG_REKEY;
		}
		outLen += enc.update(out, outLen, 1, out, outLen);
		// REKEY (option)
		byte[] newKey = null;
		if (reKey) {
			newKey = new byte[cipherKeyBits >>> 3];
			rnd.nextBytes(newKey);
			outLen += enc.update(newKey, 0, cipherKeyBits >>> 3, out, outLen);
		}
		// DATA
		outLen += enc.update(buf, off, len, out, outLen);
		// END
		outLen += enc.doFinal(out, outLen);
		// HMAC
		encMac.reset();
		encMac.update(out, 0, outLen);
		encMac.doFinal(out, outLen);
		// Log.info(this.toString() + " (code): inlen=" + len + " outlen=" + out.length + " sendSeq="
		// + sendSeq + " sendTS=" + sendTS);
		if (reKey) {
			setSecret(binaryBytesToChars(newKey, 0, newKey.length), sendSeq, wayAorB);
			Log.info(this.toString() + " (code) rekey way=" + (wayAorB ? "A" : "B") + " seq=" + sendSeq);
		}
		return out;
	}

	static final char[] binaryBytesToChars(final byte[] in, final int off, final int len) {
		final char[] b = new char[len];
		for (int i = 0; i < len; i++) {
			b[i] = (char) in[off + i];
		}
		return b;
	}

	public byte[] getIV() throws IOException, GeneralSecurityException {
		final Cipher enc = getCoder(false);
		if (enc != null)
			return enc.getIV();
		return null;
	}

	public byte[] decode(final byte[] buf, int off, final int inLen) throws IOException,
			GeneralSecurityException {
		// { IV + { SEQ(4) + TS(4) + FLAGS(1) + [REKEY] + DATA(n) }CRYPT }HMAC
		// HMAC check
		final int macLen = decMac.getMacLength();
		decMac.reset();
		decMac.update(buf, off, inLen - macLen);
		final byte[] hmac = decMac.doFinal();
		final int roff = off + inLen - macLen;
		for (int i = 0; i < hmac.length; i++) {
			if (hmac[i] != buf[i + roff]) {
				throw new GeneralSecurityException("Invalid HMAC");
			}
		}
		// IV
		final int ivLen = dec.getBlockSize();
		final byte[] iv = new byte[ivLen];
		int len = inLen - macLen;
		System.arraycopy(buf, off, iv, 0, ivLen);
		len -= ivLen;
		off += ivLen;
		final Cipher dec = getDecoder(iv);
		final int ssize = dec.doFinal(buf, off, len, buf, off);
		len = ssize;
		// SEQ(4)
		final int recvSeq = IOHelper.intFromByteArray(buf, off);
		off += 4;
		len -= 4;
		// TimeStamp(4)
		final int recvTS = IOHelper.intFromByteArray(buf, off);
		off += 4;
		len -= 4;
		// FLAGS(1)
		final int flags = buf[off];
		off += 1;
		len -= 1;
		// REKEY (option)
		final boolean reKey = ((flags & FLAG_REKEY) != 0);
		char[] newKey = null;
		if (reKey) {
			final int cipLen = cipherKeyBits >>> 3;
			newKey = binaryBytesToChars(buf, off, cipLen);
			off += cipLen;
			len -= cipLen;
		}
		// SEQ check
		final int expSeq = decSeq();
		if (recvSeq != expSeq) {
			throw new GeneralSecurityException("Invalid Sequence recv=" + recvSeq + " expected=" + expSeq);
		}
		// TimeStamp check
		final int expTS = genTS();
		if ((recvTS + Constants.SEALER_TS_WINDOW) < expTS) {
			throw new GeneralSecurityException("Invalid Timestamp recv=" + recvTS + " expected=" + expTS);
		}
		final byte[] out = new byte[len];
		System.arraycopy(buf, off, out, 0, len); // DATA
		// Log.info(this.toString() + " (decode): inlen=" + inlen + " outlen=" + out.length + " recvSeq="
		// + recvSeq + " expSeq=" + expSeq + " recvTS=" + recvTS);
		if (reKey) {
			setSecret(newKey, recvSeq, !wayAorB);
			Log.info(this.toString() + " (decode) rekey way=" + (!wayAorB ? "A" : "B") + " seq=" + recvSeq);
		}
		return out;
	}

	/**
	 * Simple Test
	 */
	public static void main(final String[] args) throws Throwable {
		final int TOTAL = (int) 1e5;
		final SealerAES sealA = new SealerAES("changeit", true);
		final SealerAES sealB = new SealerAES("changeit", false);
		final long ts = System.currentTimeMillis();
		for (int i = 0; i < TOTAL; i++) {
			final byte[] b1 = "test".getBytes(UTF8);
			final byte[] b2 = sealA.code(b1.clone(), 0, b1.length);
			final byte[] b3 = sealB.decode(b2.clone(), 0, b2.length);
			if (i == 0) {
				Log.info("b1(" + b1.length + ")=" + new String(b1, "ISO-8859-1"));
				Log.info("b2(" + b2.length + ")=" + new String(b2, "ISO-8859-1"));
				Log.info("b3(" + b3.length + ")=" + new String(b3, "ISO-8859-1"));
			}
			if (!Arrays.equals(b1, b3)) {
				Log.info("origin > code > decode > origin: dont match");
				break;
			}
		}
		Log.info("SealerAES ts=" + (System.currentTimeMillis() - ts) + " sealA=" + sealA + " sealB=" + sealB);
	}
}
