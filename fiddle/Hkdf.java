package eu.danman.mistandardauth;

  import java.security.Provider;
  import java.security.NoSuchAlgorithmException;
  import javax.crypto.Mac;
  import javax.crypto.spec.SecretKeySpec;
  import java.security.InvalidKeyException;
  import java.security.GeneralSecurityException;
  import javax.crypto.ShortBufferException;
  import javax.crypto.SecretKey;
  import java.security.NoSuchAlgorithmException;
  import java.util.Arrays;

// original at https://github.com/fineoio/fineo-client/blob/master/java/cognito-auth/src/main/java/io/fineo/client/auth/cognito/Hkdf.java

  public final class Hkdf {
    private final String hmacType;
    private final Provider c;
    private static final byte[] f14467a = new byte[0];
    private SecretKey secretKey = null;

    public static Hkdf getMacInstance(String str) throws NoSuchAlgorithmException {
        Mac.getInstance(str);
        return new Hkdf(str);
    }

    private Hkdf(String str) {
        if (str.startsWith("Hmac")) {
            this.hmacType = str;
            this.c = null;
            return;
        }
        throw new IllegalArgumentException("Invalid algorithm " + str + ". Hkdf may only be used with Hmac algorithms.");
    }

    public void checkKeyAlgoMatch(SecretKey secretKey) throws InvalidKeyException {
        if (secretKey.getAlgorithm().equals(this.hmacType)) {
            this.secretKey = secretKey;
            return;
        }
        throw new InvalidKeyException("Algorithm for the provided key must match the algorithm for this Hkdf. Expected " + this.hmacType + " but found " + secretKey.getAlgorithm());
    }

    //deriveKey
    public byte[] a(byte[] bArr, int i) throws IllegalStateException { 
        byte[] bArr2 = new byte[i];
        try {
            a(bArr, i, bArr2, 0);
            return bArr2;
        } catch (ShortBufferException e) {
            throw new RuntimeException(e);
        }
    }

    //createMAC
    private Mac a() { 
        Mac mac;
        try {
            if (this.c != null) {
                mac = Mac.getInstance(this.hmacType, this.c);
            } else {
                mac = Mac.getInstance(this.hmacType);
            }
            mac.init(this.secretKey);
            return mac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e2) {
            throw new RuntimeException(e2);
        }
    }

    //assertInitialized
    private void b() throws IllegalStateException {
        if (this.secretKey == null) {
            throw new IllegalStateException("Hkdf has not been initialized");
        }
    }

    //deriveKey
    public void a(byte[] bArr, int i, byte[] bArr2, int i2) throws ShortBufferException, IllegalStateException {
        b();
        if (i < 0) {
            throw new IllegalArgumentException("Length must be a non-negative value.");
        } else if (bArr2.length >= i2 + i) {
            Mac a2 = a();
            if (i <= a2.getMacLength() * 255) {
                byte[] bArr3 = f14467a;
                int i3 = 0;
                byte b2 = 1;
                while (i3 < i) {
                    try {
                        a2.update(bArr3);
                        a2.update(bArr);
                        a2.update(b2);
                        byte[] doFinal = a2.doFinal();
                        int i4 = i3;
                        int i5 = 0;
                        while (i5 < doFinal.length && i4 < i) {
                            try {
                                bArr2[i4] = doFinal[i5];
                                i5++;
                                i4++;
                            } catch (Throwable th) {
                                th = th;
                                bArr3 = doFinal;
                                Arrays.fill(bArr3, (byte) 0);
                                throw th;
                            }
                        }
                        b2 = (byte) (b2 + 1);
                        i3 = i4;
                        bArr3 = doFinal;
                    } catch (Throwable th2) {
                    }
                }
                Arrays.fill(bArr3, (byte) 0);
                return;
            }
            throw new IllegalArgumentException("Requested keys may not be longer than 255 times the underlying HMAC length.");
        } else {
            throw new ShortBufferException();
        }
    }

    //init
    public void a(byte[] bArr, byte[] bArr2) {
        Mac mac;
        byte[] bArr3 = bArr2 == null ? f14467a : (byte[]) bArr2.clone();
        byte[] bArr4 = f14467a;
        try {
            if (this.c != null) {
                mac = Mac.getInstance(this.hmacType, this.c);
            } else {
                mac = Mac.getInstance(this.hmacType);
            }
            if (bArr3.length == 0) {
                bArr3 = new byte[mac.getMacLength()];
                Arrays.fill(bArr3, (byte) 0);
            }
            mac.init(new SecretKeySpec(bArr3, this.hmacType));
            byte[] doFinal = mac.doFinal(bArr);
            try {
                SecretKeySpec secretKeySpec = new SecretKeySpec(doFinal, this.hmacType);
                Arrays.fill(doFinal, (byte) 0);
                checkKeyAlgoMatch((SecretKey) secretKeySpec);
                Arrays.fill(doFinal, (byte) 0);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Unexpected exception", e);
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Unexpected exception", e);
        }
    }

}
