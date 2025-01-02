import java.util.*;
import java.io.*;
import java.security.*;
import java.util.stream.Collectors;
import java.math.BigInteger;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer; 
import javax.crypto.Cipher;

class A2T5 {
    // 2 users : Alice and Bob
    static Key alicePubK;
    static Key alicePrivateK;
    static long aliceN; // (long) (Math.random() * 1000000000) + 0;;
    static long XA; // randomly chosen private key for alice
  
    static Key bobPubK; //calculated using bob actualy private key
    static Key bobPrivateK; // calculated by solving ring equation
    static long bobN; // (long) (Math.random() * 1000000000) + 0;;
    static long XB; // randomly chosen private key for alice

    static Key AES1;
    static Key AES2;
    static Key AES3;
    static Key AES4;

    static KeyPair kp1;
    static KeyPair kp2;

    static String combinedFunction;

    private static SecretKeySpec secretKey;
    private static byte[] key;

    static String signature;

    static int glue = (int) (Math.random() * 10000000) + 0;

    static private Base64.Encoder encoder = Base64.getEncoder();

    static String addZeros(String str, int n) {
        for (int i = 0; i < n; i++) {
            str = "0" + str;
        }
        return str;
    }

    // function to return the XOR of the given strings  
    static String getXOR(String a, String b) {

        // lengths of the given strings  
        int aLen = a.length();
        int bLen = b.length();

        // to make both the strings of lengths are equal
        // by inserting 0s in the beginning  
        if (aLen > bLen) {
            a = addZeros(b, aLen - bLen);
        } else if (bLen > aLen) {
            a = addZeros(a, bLen - aLen);
        }

        // updated length  
        int len = Math.max(aLen, bLen);

        // this is to store the resultant XOR  
        String res = "";

        for (int i = 0; i < len; i++) {
            if (a.charAt(i) == b.charAt(i))
                res += "0";
            else
                res += "1";
        }
        return res;
    }

    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("\n!!! ERROR while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("\\n!!! ERROR while decrypting: " + e.toString());
        }
        return null;
    }

    public static String encryptRSA(String plainText, Key publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decryptRSA(String cipherText, Key privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8);
    }

    public static KeyPair generateRSAKeys()
            throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance("RSA");
        keyPairGenerator
                .initialize(
                        512, secureRandom);
        return keyPairGenerator
                .generateKeyPair();
    }

    static void generateKey() throws Exception {

        kp2 = generateRSAKeys();
        kp1 = generateRSAKeys();
        alicePubK = kp1.getPublic();

        bobPubK = kp2.getPublic();
        bobPrivateK = kp2.getPrivate();

        byte[] aPub = alicePubK.getEncoded();
        BigInteger aP = new BigInteger(aPub);

        byte[] bPub = bobPubK.getEncoded();
        BigInteger bP = new BigInteger(bPub);
        bobPrivateK = kp2.getPrivate();

        aliceN = aP.toString().length();
        bobN = bP.toString().length();

        Writer out = null;
        try {
            out = new FileWriter("publickey.txt");
            System.out.println("\nGenerating Key at publickey.txt\n");
            out.write(aP.toString() + "\n");
            out.write(aliceN + "\n");
            out.write(bP.toString() + "\n");
            out.write(bobN + "");

        } finally {
            if (out != null)
                out.close();
        }

    }

    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    public static long convertToLong(byte[] array) {
        ByteBuffer buffer = ByteBuffer.wrap(array);
        return buffer.getLong();

    }

    static void sign() throws Exception {

        System.out.println();
        String message = "";

        try {
            File myObj = new File("message.txt");
            Scanner fileReader = new Scanner(myObj);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                message = message + data;
            }
            fileReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("\n!!! ERROR occurred.");
            e.printStackTrace();
        }

        String pubKey = "";
        String[] publicKeys;
        try {
            File myObj = new File("publickey.txt");
            Scanner fileReader = new Scanner(myObj);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                pubKey = pubKey + "," + data;
            }
            fileReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("\\n" + //
                                "!!! ERROr occurred.");
            e.printStackTrace();
        }

        publicKeys = pubKey.split(",");

        String hashKey = hash(message);

        // initialize Alice's keys
        String aPub = publicKeys[1];
        System.out.println(aPub);
        BigInteger aP = new BigInteger(aPub); //public key of alice
        aliceN = Long.parseLong(publicKeys[2]);

        // initialize Bob's keys
        String bPub = publicKeys[3];
        BigInteger bP = new BigInteger(bPub); //public key of bob
        bobN = Long.parseLong(publicKeys[4]);

        // calculating y XOR glue
        XA = (long) (Math.random() * 1000000000) + 0;

        BigInteger ya = BigInteger.valueOf(XA).modPow(aP, BigInteger.valueOf(aliceN));

        String glueString = Integer.toString(glue);
        System.out.println("\nEncrypting: " + glueString);

        String v = encrypt(glueString, hashKey);

        System.out.println("glue: " + glue);

        //System.out.println(v.length());
        //System.out.println(Long.toString(ya).length());

        String binaryV = strToBinary(v);

        String binaryYa = ya.toString(2);

        String yaXORGlue = getXOR(binaryYa, binaryV);

        yaXORGlue = binaryToText(prettyBinary(yaXORGlue));

        String combine = encrypt(yaXORGlue, hashKey); // encrypt ya XOR glue
        // the end of combination ya XOR glue
        System.out.println(combine);
        String binaryCombine = strToBinary(combine);

        XB = (long) (Math.random() * 1000000000) + 0;
        // calculate for user Bob as the signer
        BigInteger yb = BigInteger.valueOf(XB).modPow(bP, BigInteger.valueOf(bobN));

        System.out.println("yb: " + yb);

        String binaryYb = yb.toString(2);
        String ybXORyaXORv = getXOR(binaryYb, binaryCombine);
        ybXORyaXORv = binaryToText(prettyBinary(ybXORyaXORv));

        String combineFunction = encrypt(ybXORyaXORv, hashKey);
        combinedFunction = combineFunction;

        System.out.println("comb func: " + combineFunction);

        System.out.println("v: " + v);

        signature = aP + "," + bP + "," + glue + "," + XA + "," + XB;
        System.out.println("Signature: (" + signature + ")");

        Writer out = null;
        try {
            out = new FileWriter("signature.txt");
            System.out.println("\n-Generating Signature at Signature.txt-\n");

            out.write(signature);

        } finally {
            if (out != null)
                out.close();
        }
    }

    static void verify() {
        String message = "";

        try {
            File myObj = new File("message.txt");
            Scanner fileReader = new Scanner(myObj);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                message = message + data;
            }
            fileReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("\n Error occurred.");
            e.printStackTrace();
        }

        String hashKey = hash(message);

        String pubKey = "";
        String[] publicKeys;
        try {
            File myObj = new File("publickey.txt");
            Scanner fileReader = new Scanner(myObj);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                pubKey = pubKey + "," + data;
            }
            fileReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("\nError occurred.");
            e.printStackTrace();
        }

        publicKeys = pubKey.split(",");

        String signatures = "";
        String[] allSignature;
        try {
            File myObj = new File("signature.txt");
            Scanner fileReader = new Scanner(myObj);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                signatures = data;
            }
            fileReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("\nError occurred.");
            e.printStackTrace();
        }

        allSignature = signatures.split(",");
        System.out.println("");
        String aPub = publicKeys[1];
        System.out.println(aPub);
        BigInteger aP = new BigInteger(aPub); //public key of alice
        aliceN = Long.parseLong(publicKeys[2]);

        String bPub = publicKeys[3];
        BigInteger bP = new BigInteger(bPub); //public key of bob
        bobN = Long.parseLong(publicKeys[4]);

        glue = Integer.parseInt(allSignature[2]);
        // calculate y XOR Glue
        XA = Long.parseLong(allSignature[4]);

        BigInteger ya = BigInteger.valueOf(XA).modPow(aP, BigInteger.valueOf(aliceN));

        String glueString = Integer.toString(glue);
        System.out.println("\nEncrypting: " + glueString);

        String v = encrypt(glueString, hashKey);

        System.out.println("glue: " + glue);

        String binaryV = strToBinary(v);

        String binaryYa = ya.toString(2);

        String yaXORGlue = getXOR(binaryYa, binaryV);

        yaXORGlue = binaryToText(prettyBinary(yaXORGlue));

        String combine = encrypt(yaXORGlue, hashKey); // encrypting ya XOR glue
        // the combination ends ya XOR glue
        System.out.println(combine);
        String binaryCombine = strToBinary(combine);

        XB = Long.parseLong(allSignature[3]);
        // calculate for Bob is the signer
        BigInteger yb = BigInteger.valueOf(XB).modPow(bP, BigInteger.valueOf(bobN));

        System.out.println("yb: " + yb);

        String binaryYb = yb.toString(2);
        String ybXORyaXORv = getXOR(binaryYb, binaryCombine);
        ybXORyaXORv = binaryToText(prettyBinary(ybXORyaXORv));

        String combineFunction1 = encrypt(ybXORyaXORv, hashKey);

        System.out.println("comb func 1: " + combinedFunction.substring(0, 21));
        System.out.println("comb func 2: " + combineFunction1.substring(0, 21));

        if (combinedFunction.substring(0, 21).equals(combineFunction1.substring(0, 21))) {
            System.out.println("Verified\n");
        } else {
            System.out.println("Not Verified\n");
        }

    }

    public static void main(String[] args) throws Exception {
        Scanner obj = new Scanner(System.in);

        int choose = 99;
        do {
            System.out.println("\n======= Ring Signature =======");
            System.out.println("1. Generate Key");
            System.out.println("2. Sign");
            System.out.println("3. Verify");
            System.out.println("4. Quit");
            System.out.print("Enter an option >> ");

            choose = obj.nextInt();

            if (choose == 1) {
                generateKey();
            }
            if (choose == 2) {
                sign();
            }
            if (choose == 3) {
                verify();
            }

        } while (choose != 4);

        System.out.println("\n- The program quit. -");

    }

    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    static String hash(String text) {
        try {
            // getInstance() method is called with algorithm SHA-1 
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            // digest() method is called 
            // to calculate message digest of the input string 
            // returned as array of byte 
            byte[] messageDigest = md.digest(text.getBytes());

            // convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest);

            // convert message digest into hex value 
            String hashtext = no.toString(16);

            // add preceding 0s to make it 128 bit
            // the reason i use 128 so its able to send long messages, but it still has limits 
            while (hashtext.length() < 128) {
                hashtext = "0" + hashtext;
            }

            // return the HashText 
            return hashtext;
        }

        // to specify the  wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static String strToBinary(String input) {
        StringBuilder result = new StringBuilder();
        char[] chars = input.toCharArray();
        for (char aChar : chars) {
            result.append(
                    String.format("%8s", Integer.toBinaryString(aChar)) // char -> int, auto-cast
                            .replaceAll(" ", "0") // zero pads
            );
        }
        return result.toString();
    }

    public static String prettyBinary(String binary) {

        List<String> result = new ArrayList<>();
        int index = 0;
        while (index < binary.length()) {
            result.add(binary.substring(index, Math.min(index + 8, binary.length())));
            index += 8;
        }

        return result.stream().collect(Collectors.joining(" "));
    }

    static String reverse(String input) {
        char[] a = input.toCharArray();
        int l, r = 0;
        r = a.length - 1;

        for (l = 0; l < r; l++, r--) {
            // swap values of l and r  
            char temp = a[l];
            a[l] = a[r];
            a[r] = temp;
        }
        return String.valueOf(a);
    }

    static String binaryToText(String input) {
        if (input == null || input.isEmpty()) {
            return "Invalid or empty input";
        }
    
        StringBuilder raw = new StringBuilder();
        String[] binaryNumbers = input.split(" ");
    
        for (String binaryNumber : binaryNumbers) {
            int decimalNumber = Integer.parseInt(binaryNumber, 2);
            raw.append((char) decimalNumber);
        }
    
        return raw.toString();
    }
}