package com.scio;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;


public class Main {

    static String msg = "Hello World";
    static String pwd = "l33t_h4x0r_xD";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please enter mode:");
        System.out.println("    '0': Demo");
        System.out.println("    '1': Encrypt");
        System.out.println("    '2': Decrypt");
        String str = scanner.nextLine();
        if(str.length() == 1)
        {
            if(str.charAt(0) == '0')
            {
                System.out.println("--------Originals--------");
                System.out.println("Msg: " + msg);
                System.out.println("Pwd: " + pwd);
                System.out.println();
                System.out.println("--------Encrypting--------");
                String[] s = Encrypt(msg, pwd.toCharArray());
                if(s != null && s.length > 2)
                {
                    System.out.println("Salt:        " + s[0]);
                    System.out.println("Iv:          " + s[1]);
                    System.out.println("Ciphertext:  " + s[2]);
                }
                System.out.println();
                System.out.println("--------Decrypting--------");
                System.out.println("Decrypted msg: " + Decrypt(s, pwd.toCharArray()));
                System.out.println("----------------");
            }
            else if(str.charAt(0) == '1')
            {
                System.out.println("Please enter Message");
                String newMsg = scanner.nextLine();
                System.out.println("Please enter Password");
                char[] newPwd = scanner.nextLine().toCharArray();
                String[] s = Encrypt(newMsg, newPwd);
                Arrays.fill(newPwd, '0');
                System.out.println("Results:");
                if(s != null && s.length > 2)
                {
                    System.out.println("Salt:        " + s[0]);
                    System.out.println("Iv:          " + s[1]);
                    System.out.println("Ciphertext:  " + s[2]);
                }
            }
            else if(str.charAt(0) == '2')
            {
                String[] raw = new String[3];
                System.out.println("Please enter Salt");
                raw[0] = scanner.nextLine();
                System.out.println("Please enter Iv");
                raw[1] = scanner.nextLine();
                System.out.println("Please enter Ciphertext");
                raw[2] = scanner.nextLine();
                System.out.println("Please enter Password");
                char[] newPwd = scanner.nextLine().toCharArray();

                System.out.println("Result:");
                try {
                    System.out.println(Decrypt(raw, newPwd));
                    Arrays.fill(newPwd, '0');
                } catch(Exception e)
                {
                    Arrays.fill(newPwd, '0');
                    e.printStackTrace();
                }
            }
        }
    }

    public static String[] Encrypt(String str, char[] pwd) {
        try {
            byte[] salt = new byte[32];
            byte[] iv = new byte[16];
            SecureRandom.getInstance("SHA1PRNG").nextBytes(salt);
            SecureRandom.getInstance("SHA1PRNG").nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            KeySpec kSpec = new PBEKeySpec(pwd, salt, 65536, 256);
            SecretKey k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(kSpec);
            SecretKeySpec k2 = new SecretKeySpec(k.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, k2, ivSpec);
            return new String[]{Base64.getEncoder().encodeToString(salt),
                    Base64.getEncoder().encodeToString(iv),
                    Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes()))};
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String Decrypt(String[] cipherCode, char[] pwd) {
        try {
            byte[] salt = Base64.getDecoder().decode(cipherCode[0]);
            byte[] iv = Base64.getDecoder().decode(cipherCode[1]);
            byte[] cc = Base64.getDecoder().decode(cipherCode[2]);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            KeySpec kSpec = new PBEKeySpec(pwd, salt, 65536, 256);
            SecretKey k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(kSpec);
            SecretKeySpec k2 = new SecretKeySpec(k.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, k2, ivSpec);
            return new String(cipher.doFinal(cc));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

}
