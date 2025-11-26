package com.demo;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.net.ssl.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLConnection;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Logger;

public class App {

    private static final Logger logger = Logger.getLogger("VulnerableLogger");

    // Hardcoded credentials & secrets
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "Harshjeet&^%$#"; // SAST Issue
    private static final String API_KEY = "AKIAEXAMPLEHARDCODEDKEY"; // Hardcoded API key
    private static final String SSH_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...FAKE...IDAQAB\n-----END RSA PRIVATE KEY-----";

    public static void main(String[] args) throws Exception {
        System.out.println("Windows Agent Checkmarx All Scans Test");

        // Existing vulnerabilities
        weakCrypto();
        insecureRandom();
        logSensitiveData();
        brokenAuthentication("admin");
        pathTraversal("../secret.txt");
        insecureDeserialization();       // local file deserialization
        commandInjection("dir");
        sqlInjection("admin' OR '1'='1");
        insecureFileUpload("malware.exe", "virus".getBytes());
        debugMode();

        // New/expanded vulnerabilities
        xxeVulnerability("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>");
        ldapInjection("*)(uid=*))(|(uid=*"); // demonstrates string construction issue
        startInsecureHttpServer(8080);

        trustAllSsl();                     // disables SSL verification
        insecureUrlConnection("https://self-signed.example.com"); // uses trust-all

        reflectionInjection("java.lang.Runtime"); // dangerous reflective instantiation
        insecureProcessBuilder("calc.exe");       // runs a command built from input

        createPredictableTempFile();        // predictable temp file
        writeWorldReadableFile("secrets.txt", "TOP-SECRET=" + API_KEY); // world readable file

        deserializationFromSocket(9999);    // listens and deserializes incoming objects (unsafe)
        aesEcbEncryption("secret-data");    // AES in ECB (insecure pattern)

        // Simulate leaking secrets to logs / env
        simulateEnvSecretLeak();

        System.out.println("Extended vulnerable app finished.");
    }

    // -------------------------------------------------
    // WEAK CRYPTO (MD5)
    static void weakCrypto() throws Exception {
        String password = "admin123";
        MessageDigest md = MessageDigest.getInstance("MD5"); // Weak Algorithm
        byte[] hash = md.digest(password.getBytes());
        System.out.println("Weak hash (MD5): " + Base64.getEncoder().encodeToString(hash));
    }

    // -------------------------------------------------
    // INSECURE RANDOM (java.util.Random)
    static void insecureRandom() {
        Random random = new Random(); // Predictable
        int token = random.nextInt(999999);
        System.out.println("Predictable token: " + token);
    }

    // -------------------------------------------------
    // SENSITIVE DATA LOGGING
    static void logSensitiveData() {
        String creditCard = "4111-1111-1111-1111";
        logger.info("User credit card: " + creditCard); // Sensitive data leak
        System.out.println("DB password (leaked): " + DB_PASSWORD); // printing secret
    }

    // -------------------------------------------------
    // BROKEN AUTHENTICATION (==)
    static void brokenAuthentication(String inputPassword) {
        String realPassword = "admin";
        if (inputPassword == realPassword) { // Vulnerable (== instead of equals)
            System.out.println("Access Granted");
        } else {
            System.out.println("Access Denied");
        }
    }

    // -------------------------------------------------
    // PATH TRAVERSAL
    static void pathTraversal(String filename) throws Exception {
        File file = new File("C:/app/data/" + filename); // No validation
        BufferedReader reader = new BufferedReader(new FileReader(file));
        System.out.println("First line: " + reader.readLine());
        reader.close();
    }

    // -------------------------------------------------
    // INSECURE DESERIALIZATION (from local file)
    static void insecureDeserialization() throws Exception {
        File f = new File("data.bin");
        if (!f.exists()) {
            // create a dummy file so this doesn't always fail in tests
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(f))) {
                oos.writeObject("dummy");
            }
        }
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            Object obj = ois.readObject(); // Unsafe if file is untrusted
            System.out.println("Deserialized object: " + obj);
        }
    }

    // -------------------------------------------------
    // COMMAND INJECTION (Runtime.exec)
    static void commandInjection(String command) throws Exception {
        // direct concatenation of untrusted input into command
        Runtime.getRuntime().exec("cmd.exe /c " + command); // Injection risk on Windows
    }

    // -------------------------------------------------
    // SQL INJECTION (concatenated query)
    static void sqlInjection(String userInput) throws Exception {
        // (Note: requires jdbc driver on classpath; this demonstrates pattern)
        try {
            Connection conn = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/test", DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
            ResultSet rs = stmt.executeQuery(query); // Vulnerable
            while (rs.next()) {
                System.out.println("user: " + rs.getString("username"));
            }
            conn.close();
        } catch (Exception e) {
            // swallow - this demo may not have DB available
            logger.warning("DB connection failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------
    // INSECURE FILE UPLOAD (no validation)
    static void insecureFileUpload(String filename, byte[] data) throws Exception {
        File out = new File("uploads/" + filename); // No validation or sanitization
        out.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(data);
        }
        System.out.println("Wrote uploaded file: " + out.getAbsolutePath());
    }

    // -------------------------------------------------
    // DEBUG MODE ENABLED
    static void debugMode() {
        boolean DEBUG = true; // Vulnerable setting
        if (DEBUG) {
            System.out.println("Debug mode enabled in production!");
        }
    }

    // -------------------------------------------------
    // XXE (XML External Entity) - naive XML parser
    static void xxeVulnerability(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // NOT disabling external entities -> vulnerable to XXE
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new org.xml.sax.InputSource(new StringReader(xml)));
        System.out.println("Parsed XML (no XXE protections)");
    }

    // -------------------------------------------------
    // LDAP INJECTION (string building)
    static void ldapInjection(String userInput) {
        // dangerous concatenation of user input into LDAP filter
        String filter = "(&(objectClass=person)(uid=" + userInput + "))";
        System.out.println("LDAP filter: " + filter);
    }

    // -------------------------------------------------
    // START INSECURE HTTP SERVER (demonstrate many OWASP issues)
    static void startInsecureHttpServer(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        // reflected XSS / command execution endpoint
        server.createContext("/exec", new HttpHandler() {
            public void handle(HttpExchange exchange) throws IOException {
                String query = exchange.getRequestURI().getQuery();
                String cmd = "echo no-cmd";
                if (query != null && query.contains("cmd=")) {
                    cmd = query.split("cmd=")[1].split("&")[0]; // unsafe parsing
                }
                // reflected XSS in response
                String response = "<html><body>Ran: " + cmd + "</body></html>";
                exchange.getResponseHeaders().add("Content-Type", "text/html");
                // Host header trust (used to build links) - vulnerable pattern
                String host = exchange.getRequestHeaders().getFirst("Host");
                if (host == null) host = "localhost";
                response += "<p>Reset link: https://" + host + "/reset?token=123</p>";
                // insecure command execution using ProcessBuilder -> command injection
                try {
                    new ProcessBuilder("cmd.exe", "/c", cmd).start();
                } catch (Exception e) {
                    // ignore
                }
                exchange.sendResponseHeaders(200, response.getBytes().length);
                exchange.getResponseBody().write(response.getBytes());
                exchange.close();
            }
        });

        // open redirect - redirects to provided url (no validation)
        server.createContext("/redir", new HttpHandler() {
            public void handle(HttpExchange exchange) throws IOException {
                String query = exchange.getRequestURI().getQuery();
                String url = "http://example.com";
                if (query != null && query.contains("url=")) {
                    url = query.split("url=")[1].split("&")[0]; // no validation
                }
                exchange.getResponseHeaders().add("Location", url);
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
            }
        });

        // insecure CORS (wildcard)
        server.createContext("/data", new HttpHandler() {
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                String body = "{\"data\":\"public\"}";
                exchange.sendResponseHeaders(200, body.getBytes().length);
                exchange.getResponseBody().write(body.getBytes());
                exchange.close();
            }
        });

        // endpoint that intentionally exposes stack traces
        server.createContext("/boom", new HttpHandler() {
            public void handle(HttpExchange exchange) throws IOException {
                try {
                    throw new RuntimeException("Intentional failure");
                } catch (Exception e) {
                    // exposing stack trace to client
                    StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    String resp = "<pre>" + sw.toString() + "</pre>";
                    exchange.sendResponseHeaders(500, resp.getBytes().length);
                    exchange.getResponseBody().write(resp.getBytes());
                    exchange.close();
                }
            }
        });

        Thread t = new Thread(server::start);
        t.setDaemon(true);
        t.start();
        System.out.println("Insecure HTTP server started on port " + port);
    }

    // -------------------------------------------------
    // Trust-all SSL/TLS (disables hostname + cert validation)
    static void trustAllSsl() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        // disable hostname verification
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        System.out.println("Disabled SSL certificate validation (trust-all)");
    }

    // -------------------------------------------------
    // Insecure URLConnection that will accept any certificate
    static void insecureUrlConnection(String urlStr) {
        try {
            URL url = new URL(urlStr);
            URLConnection conn = url.openConnection(); // will use trust-all from above
            try (InputStream in = conn.getInputStream()) {
                // read a bit (not doing anything secure)
                byte[] buf = new byte[64];
                in.read(buf);
            }
            System.out.println("Made insecure URL connection to " + urlStr);
        } catch (Exception e) {
            logger.warning("Could not open insecure connection: " + e.getMessage());
        }
    }

    // -------------------------------------------------
    // Reflection injection (Class.forName on untrusted input)
    static void reflectionInjection(String className) {
        try {
            // untrusted class name may lead to loading unexpected classes
            Class<?> c = Class.forName(className);
            Object inst = c.getDeclaredConstructor().newInstance();
            System.out.println("Reflected instance: " + inst.getClass().getName());
        } catch (Exception e) {
            logger.warning("Reflection failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------
    // ProcessBuilder with user input (insecure)
    static void insecureProcessBuilder(String cmd) {
        try {
            // building a command using untrusted input
            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", cmd);
            pb.start(); // may execute arbitrary command
            System.out.println("Started process for: " + cmd);
        } catch (Exception e) {
            logger.warning("ProcessBuilder failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------
    // Predictable temp file name
    static void createPredictableTempFile() throws IOException {
        File predictable = new File(System.getProperty("java.io.tmpdir"), "app_temp_12345.tmp");
        try (FileWriter fw = new FileWriter(predictable)) {
            fw.write("predictable data");
        }
        System.out.println("Created predictable temp file at: " + predictable.getAbsolutePath());
    }

    // -------------------------------------------------
    // Create a world-readable file (simulate bad permissions)
    static void writeWorldReadableFile(String name, String contents) throws IOException {
        File f = new File(name);
        try (FileWriter fw = new FileWriter(f)) {
            fw.write(contents);
        }
        // make readable/writable by everyone (best-effort)
        f.setReadable(true, false);
        f.setWritable(true, false);
        System.out.println("Wrote world-readable files: " + f.getAbsolutePath());
    }

    // -------------------------------------------------
    // Listen on socket and deserialize incoming objects (unsafe)
    static void deserializationFromSocket(int port) {
        Thread t = new Thread(() -> {
            try (java.net.ServerSocket serverSocket = new java.net.ServerSocket(port)) {
                serverSocket.setSoTimeout(2000); // short timeout so demo doesn't hang forever
                java.net.Socket client = null;
                try {
                    client = serverSocket.accept(); // blocking until a client connects
                    ObjectInputStream ois = new ObjectInputStream(client.getInputStream());
                    Object o = ois.readObject(); // dangerous: remote deserialization
                    System.out.println("Deserialized remote object: " + o);
                    ois.close();
                    client.close();
                } catch (java.net.SocketTimeoutException ste) {
                    // no client connected - fine for demo
                }
            } catch (Exception e) {
                logger.warning("Deserialization socket failed: " + e.getMessage());
            }
        });
        t.setDaemon(true);
        t.start();
        System.out.println("Started deserialization listener on ports " + port + " (unsafe)");
    }

    // -------------------------------------------------
    // AES ECB encryption (insecure usage pattern)
    static void aesEcbEncryption(String plain) {
        try {
            // NOTE: This is pseudo-demo code and does not perform proper key management
            byte[] keyBytes = "0123456789abcdef".getBytes(); // 16 bytes key (weak storage)
            javax.crypto.spec.SecretKeySpec key = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB mode is insecure
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(plain.getBytes());
            System.out.println("AES-ECB(encrypted): " + Base64.getEncoder().encodeToString(encrypted));
        } catch (Exception e) {
            logger.warning("AES ECB failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------
    // Simulate leaking secrets to logs / storing in env-like map
    static void simulateEnvSecretLeak() {
        java.util.Map<String, String> envLike = new java.util.HashMap<>();
        envLike.put("DB_PASSWORD", DB_PASSWORD); // storing secret in a map and logging it
        envLike.put("SSH_KEY", SSH_PRIVATE_KEY);
        logger.info("ENV LEAK: DB_PASSWORD=" + envLike.get("DB_PASSWORD"));
        logger.info("ENV LEAK: SSH_KEYS=" + envLike.get("SSH_KEYS"));

    }

}


