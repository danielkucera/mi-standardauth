  import java.security.KeyPairGenerator;
  import java.security.spec.ECGenParameterSpec;
  import java.security.interfaces.ECPublicKey;
  import java.security.spec.ECPoint;
  import java.security.KeyPair;
  import java.security.PublicKey;
  import java.util.Arrays;
  
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
            System.out.printf("\n");
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }
  }
