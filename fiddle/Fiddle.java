  import java.security.KeyPairGenerator;
  import java.security.spec.ECGenParameterSpec;
  import java.security.interfaces.ECPublicKey;
  import java.security.spec.ECPoint;
  import java.security.spec.ECParameterSpec;
  import java.security.spec.ECPublicKeySpec;
  import java.security.KeyPair;
  import java.security.KeyFactory;
  import java.security.PublicKey;
  import java.security.PrivateKey;
  import java.util.Arrays;
  import java.math.BigInteger;
  import java.io.InputStreamReader;
  import java.io.BufferedReader;
  import javax.crypto.KeyAgreement;
  import javax.crypto.SecretKey;

  public class Fiddle
  {
    public static final String RECHARGE_MODE_DESIGNATED_AND_CACH = "04";
      
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator instance = KeyPairGenerator.getInstance("EC");
            instance.initialize(new ECGenParameterSpec("secp256r1"));
            return instance.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    protected static int hexToInt(char c, int i) throws IllegalArgumentException {
        int digit = Character.digit(c, 16);
        if (digit != -1) {
            return digit;
        }
        throw new IllegalArgumentException("Illegal hexadecimal character " + c + " at index " + i);
    }
    
    public static byte[] hexArrayToByte(char[] cArr) throws IllegalArgumentException {
        int length = cArr.length;
        if ((length & 1) == 0) {
            byte[] bArr = new byte[(length >> 1)];
            int i = 0;
            int i2 = 0;
            while (i < length) {
                int c1 = hexToInt(cArr[i], i) << 4;
                i++;
                int c2 = hexToInt(cArr[i], i);
                i++;
                bArr[i2] = (byte)((c1 | c2) & 0xff);
                i2++;
            }
            return bArr;
        }
        throw new IllegalArgumentException("Odd number of characters.");
    }
      
    public static byte[] getWCoords(ECPublicKey eCPublicKey) throws IllegalArgumentException {
        ECPoint w = eCPublicKey.getW();
        String bigInteger = w.getAffineX().toString(16);
        String bigInteger2 = w.getAffineY().toString(16);
        StringBuilder sb = new StringBuilder();
        sb.append(RECHARGE_MODE_DESIGNATED_AND_CACH);
        for (int i = 0; i < 64 - bigInteger.length(); i++) {
            sb.append(0);
        }
        sb.append(bigInteger);
        for (int i2 = 0; i2 < 64 - bigInteger2.length(); i2++) {
            sb.append(0);
        }
        sb.append(bigInteger2);
        return hexArrayToByte(sb.toString().toCharArray());
    }
    
    public static byte[] formatPubKey(PublicKey publicKey) {
        byte[] b = getWCoords((ECPublicKey) publicKey);
        return b.length == 65 ? Arrays.copyOfRange(b, 1, 65) : b;
    }

    public static ECPublicKey decodePublicKey(byte[] bArr, ECParameterSpec eCParameterSpec) throws Exception {
        if (bArr[0] == 4) {
            int bitLength = ((eCParameterSpec.getOrder().bitLength() + 8) - 1) / 8;
            if (bArr.length == (bitLength * 2) + 1) {
                int i = 1 + bitLength;
                return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(1, Arrays.copyOfRange(bArr, 1, i)), new BigInteger(1, Arrays.copyOfRange(bArr, i, bitLength + i))), eCParameterSpec));
            }
            throw new IllegalArgumentException("Invalid uncompressedPoint encoding, not the correct size");
        }
        throw new IllegalArgumentException("Invalid uncompressedPoint encoding, no uncompressed point indicator");
    }

    public static SecretKey decodeEShareKey(PublicKey publicKey, PrivateKey privateKey) {
        try {
            KeyAgreement instance = KeyAgreement.getInstance("ECDH");
            instance.init(privateKey);
            instance.doPhase(publicKey, true);
            return instance.generateSecret("ECDH");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args)
    {
        try {
            KeyPairGenerator instance = KeyPairGenerator.getInstance("EC");
            instance.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = generateKeyPair();
            byte[] DTS = formatPubKey(keyPair.getPublic());
            for (int i=0; i<DTS.length; i++){
                System.out.printf("%02X", DTS[i]);
            }
            System.out.printf("\nEnter key from device:\n");

            BufferedReader buffer = new BufferedReader(new InputStreamReader(System.in));
            String devKey = buffer.readLine();
            System.out.printf("Entered key:\n%s\n", devKey);

            byte[] bArr2 = new byte[65];
            bArr2[0] = 4;
            for (int i=0; i<64; i++){
                bArr2[i+1] = (byte) ((Character.digit(devKey.charAt(i), 16) << 4)
                             + Character.digit(devKey.charAt(i+1), 16));
            }

            PublicKey mDevicePubKey = decodePublicKey(bArr2, ((ECPublicKey) keyPair.getPublic()).getParams());
            SecretKey eShareKey = decodeEShareKey(mDevicePubKey, keyPair.getPrivate());

        }
        catch (Exception e) {
            System.out.println(e);
        }
    }
  }
