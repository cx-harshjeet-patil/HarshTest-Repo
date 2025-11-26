package com.demo;

import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Logger;


public class App {

    private static final Logger logger = Logger.getLogger("VulnerableLogger");

    // 1️⃣ HARDCODED CREDENTIALS
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "Harshjeet&^%$#"; // SAST Issue

    public static void main(String[] args) throws Exception {

        System.out.println("Windows Agent Checkmarx All Scans Test");

        // 2️⃣ WEAK CRYPTO (MD5)
        weakCrypto();

        // 3️⃣ INSECURE RANDOM
        insecureRandom();

        // 4️⃣ SENSITIVE DATA IN LOGS
        logSensitiveData();

        // 5️⃣ BROKEN AUTHENTICATION
        brokenAuthentication("admin");

        // 6️⃣ PATH TRAVERSAL
        pathTraversal("../secret.txt");

        // 7️⃣ INSECURE DESERIALIZATION
        insecureDeserialization();

        // 8️⃣ COMMAND INJECTION
        commandInjection("dir");

        // 9️⃣ SQL INJECTION
        sqlInjection("admin' OR '1'='1");

        // 🔟 INSECURE FILE UPLOAD
        insecureFileUpload("malware.exe", "virus".getBytes());
    }

    // -----------------------------------------
    // WEAK CRYPTO
    static void weakCrypto() throws Exception {
        String password = "admin123";
        MessageDigest md = MessageDigest.getInstance("MD5"); // Weak Algorithm
        byte[] hash = md.digest(password.getBytes());
        System.out.println("Weak hash: " + hash);
    }

    // -----------------------------------------
    // INSECURE RANDOM
    static void insecureRandom() {
        Random random = new Random(); // Predictable
        int token = random.nextInt(999999);
        System.out.println("Token: " + token);
    }

    // -----------------------------------------
    // SENSITIVE DATA LOGGING
    static void logSensitiveData() {
        String creditCard = "4111-1111-1111-1111";
        logger.info("User credit card: " + creditCard); // Sensitive data leak
    }

    // -----------------------------------------
    // BROKEN AUTH
    static void brokenAuthentication(String inputPassword) {
        String realPassword = "admin";
        if (inputPassword == realPassword) { // Vulnerable (== instead of equals)
            System.out.println("Access Granted");
        }
    }

    // -----------------------------------------
    // PATH TRAVERSAL
    static void pathTraversal(String filename) throws Exception {
        File file = new File("C:/app/data/" + filename); // No validation
        BufferedReader reader = new BufferedReader(new FileReader(file));
        System.out.println(reader.readLine());
        reader.close();
    }

    // -----------------------------------------
    // INSECURE DESERIALIZATION
    static void insecureDeserialization() throws Exception {
        ObjectInputStream ois =
                new ObjectInputStream(new FileInputStream("data.bin"));
        Object obj = ois.readObject(); // Unsafe
        ois.close();
        System.out.println(obj);
    }

    // -----------------------------------------
    // COMMAND INJECTION
    static void commandInjection(String command) throws Exception {
        Runtime.getRuntime().exec("cmd.exe /c " + command); // Injection risk
    }

    // -----------------------------------------
    // SQL INJECTION
    static void sqlInjection(String userInput) throws Exception {

        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/test", DB_USER, DB_PASSWORD);

        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        ResultSet rs = stmt.executeQuery(query); // Vulnerable

        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }

        conn.close();
    }

    // -----------------------------------------
    // INSECURE FILE UPLOAD
    static void insecureFileUpload(String filename, byte[] data) throws Exception {
        FileOutputStream fos =
                new FileOutputStream("uploads/" + filename); // No validation
        fos.write(data);
        fos.close();
    }

    // -----------------------------------------
    // DEBUG MODE ENABLED
    static void debugMode() {
        boolean DEBUG = true; // Vulnerable setting
        if (DEBUG) {
            System.out.println("Debug mode enabled in production!");
        }
    }
    // -----------------------------------------
    // JWT NONE ALGORITHM BYPASS
    static void jwtNoneAlgorithm(String token) {
        String[] parts = token.split("\\.");
        byte[] decoded = Base64.getDecoder().decode(parts[1]);
        System.out.println("JWT Payload without verification: " + new String(decoded));
    }

    // -----------------------------------------
    // RACE CONDITION
    static int counter = 0;
    static void raceCondition() {
        new Thread(() -> counter++).start();
        new Thread(() -> counter++).start();
    }

    // -----------------------------------------
    // INSECURE TEMP FILE
    static void tempFileInsecure() throws Exception {
        File temp = File.createTempFile("temp", ".txt");
        FileWriter writer = new FileWriter(temp);
        writer.write("Sensitive temp data");
        writer.close();
        System.out.println("Temp file: " + temp.getAbsolutePath());
    }

    // -----------------------------------------
    // STACK TRACE EXPOSURE
    static void stackTraceExposure() {
        try {
            int x = 10 / 0;
        } catch (Exception e) {
            e.printStackTrace(); // Information disclosure
        }
    }
}
