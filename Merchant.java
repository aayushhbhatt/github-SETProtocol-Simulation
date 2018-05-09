/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Components;

/**
 *
 * @author Deep
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.*;
import OrderInfo.Order;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DecimalFormat;
import java.time.LocalTime;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.swing.JTextArea;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 *
 * @author Alvin
 */
public class Merchant {

    static X509Certificate bankcertificate;
    static X509Certificate customercertificate;
    JTextArea logging;
    ServerSocket MerchantServer = null;
    Socket clientSocket = null;
    Socket Bank = null;
    ObjectOutputStream b_os2 = null; // Bank output stream
    ObjectInputStream b_is2 = null; // Bank input stream
    ObjectOutputStream c_os = null; //Client output stream
    ObjectInputStream c_is = null; //Client input stream
    String transcationID;
    static CertAndKeyGen keypair = generateKeypair(); // Generating keypair for merchant
    static X509Certificate merchantcertificate = createcertificate(keypair); //Self signed certificate
    static RequestMessage message = new RequestMessage(); //Request Message that needs to be sent around
    static RequestMessage purchasemessage = new RequestMessage();
    static Order order;
    boolean bank_connected = false;
    boolean server_opened = false;
    DecimalFormat numberFormat = new DecimalFormat("#.00");
    LocalTime localTime;

    public Merchant(JTextArea textarea) {
        this.logging = textarea;
    }

    public void openclientserver() throws Exception {
        if (server_opened == false) {
            MerchantServer = new ServerSocket(9999);
            clientSocket = MerchantServer.accept();
            server_opened = true;
            c_os = new ObjectOutputStream(clientSocket.getOutputStream());
            c_is = new ObjectInputStream(clientSocket.getInputStream());
            logging.append(localTime.now()+" Client 1 has connected\n\n");
        } else {
            logging.append(localTime.now()+" Client has already connected\n");
        }
    }

    public void connecttobank() throws IOException, ClassNotFoundException {
        if (bank_connected == false) {
            Bank = new Socket("127.0.0.1", 1000);
            b_is2 = new ObjectInputStream(Bank.getInputStream());
            b_os2 = new ObjectOutputStream(Bank.getOutputStream());
            bankcertificate = (X509Certificate) b_is2.readObject();
            bank_connected = true;
            logging.append(localTime.now()+" Connected to bank\n\n");
        } else {
            logging.append(localTime.now()+" Connected to bank already...\n");
        }
    }
    
    public void retriveclientbankbalance(){
        try {
            b_os2.writeUTF("Check Balance");
            b_os2.flush();
            Double amount = b_is2.readDouble();
            c_os.writeDouble(amount);
            c_os.flush();
            reset();
        } catch (IOException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void initiaterequest() throws Exception {
        RequestMessage initmessage = new RequestMessage();
        initmessage.clearvariables();
        if (bank_connected == true) {
            if(c_is.readUTF().contains("Check Balance")){
                retriveclientbankbalance();
            } else {
                b_os2.writeUTF(" ");
            b_os2.flush();
            initmessage = (RequestMessage) c_is.readObject();
            if (initmessage.InitStringMessage.contains("Initiate")) {
                logging.append(localTime.now()+" Start of initateresponse\n");
                //assign a unique transcation id 
                message.clearvariables();
                transcationID = UUID.randomUUID().toString();
                message.InitStringMessage.add(transcationID);
                message.certificates.add(merchantcertificate);
                message.certificates.add(bankcertificate);
                c_os.writeObject(message);
                logging.append(localTime.now()+" Finish initateresponse\n\n");
                purchasemessage.clearvariables();
                purchasemessage = (RequestMessage) c_is.readObject();
                if (purchasemessage.InitStringMessage.contains("Purchase Request")) {
                    purchaserequestprocessing();
                    authorizationrequest();
                }
                responseprocessing();
                payementcapturerequest();
                processingofresponse();
            } else {
                logging.append(localTime.now()+" Bank not connected\n");
            }
            }
        }
    }

    public void purchaserequestprocessing() throws Exception {
        logging.append(localTime.now()+" Start of purchase request processing\n");
        customercertificate = purchasemessage.certificates.get(0);
        SealedObject s_order = purchasemessage.sealedobject.get(1);
        // Decrypting the order object using own private key
        try {
            Cipher desCipher2 = Cipher.getInstance("RSA");
            Key sessionkey;
            desCipher2.init(Cipher.UNWRAP_MODE, keypair.getPrivateKey());
            sessionkey = desCipher2.unwrap(purchasemessage.encrypteddata.get(2), "AES", Cipher.SECRET_KEY);

            // Decrypting the order object using the unwrapped session key
            Cipher desCipher = Cipher.getInstance("AES");
            desCipher.init(Cipher.DECRYPT_MODE, sessionkey);
            order = (Order) s_order.getObject(desCipher);
            logging.append(localTime.now()+" Recieved the order from client: " + order.getTransaction_id() + "\n");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
        ///CHECK IF DUAL SIGNATURE IS CORRECT
        logging.append(localTime.now()+" Start of dual signature check\n");
        byte[] dual_signature = purchasemessage.encrypteddata.get(0);
        byte[] orderdigest = purchasemessage.encrypteddata.get(3);
        byte[] paymentdigest = purchasemessage.encrypteddata.get(4);

        MessageDigest duals = MessageDigest.getInstance("SHA-1");
        duals.update(orderdigest);
        duals.update(paymentdigest);
        byte[] combinedMD = duals.digest(); // Create the digest of the combined
        boolean check = verifySignature(combinedMD, dual_signature);
        //send purchase response 
        if (check == true) {
            logging.append(localTime.now()+"Dual Signature verification done: " + check + "\n");
            c_os.writeUTF("Purchase Processing Completed");
            c_os.flush();
            logging.append(localTime.now()+" Finish purchase request processing\n\n");
        }
    }

    // Used to verify the digital signature, params are data to be checked and the signature
    public boolean verifySignature(byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(customercertificate.getPublicKey());
        sig.update(data);
        return sig.verify(signature);
    }

    //Payment authorization phase
    public void authorizationrequest() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        logging.append(localTime.now()+" Start authorization request processing\n");
        message.clearvariables();
        message.InitStringMessage.add("Authorization Request");

        //generate sessionkey
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey sessionkey = kgen.generateKey();

        Cipher desCipher;
        desCipher = Cipher.getInstance("AES");
        //encrypt using session key
        desCipher.init(Cipher.ENCRYPT_MODE, sessionkey);
        desCipher.update((numberFormat.format(order.getTotal()) + ":").getBytes());
        byte[] encrpyted1 = desCipher.doFinal(order.getTransaction_id().getBytes());

        Cipher desCipher2;
        desCipher2 = Cipher.getInstance("RSA");
        desCipher2.init(Cipher.WRAP_MODE, bankcertificate.getPublicKey());
        byte[] wrappedsessionkey = desCipher2.wrap(sessionkey);
        //Add encrypted amount+transactionid in ecrypteddata index 0
        //Add wrapped sessionkey 2 into encrypteddata index 1
        message.encrypteddata.add(encrpyted1);
        message.encrypteddata.add(wrappedsessionkey);

        //Payment Sealed object in index 0 of sealedobject
        // Session key 1 into the ecrypteddata index 2
        message.sealedobject.add(purchasemessage.sealedobject.get(0));
        message.encrypteddata.add(purchasemessage.encrypteddata.get(1));

        //Add customercertificate in index 0 and merchantcertificate in 1
        message.certificates.add(customercertificate);
        message.certificates.add(merchantcertificate);

        b_os2.writeObject(message);
        logging.append(localTime.now()+" Sent the authorization message\n");
        logging.append(localTime.now()+" Finish authorization request processing\n\n");
    }

    public void responseprocessing() throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        message.clearvariables();
        message = (RequestMessage) b_is2.readObject();

        logging.append(localTime.now()+" Start Authorization Response Processing\n");

        Cipher desCipher = Cipher.getInstance("RSA");
        desCipher.init(Cipher.UNWRAP_MODE, keypair.getPrivateKey());

        SecretKey sessionKey3 = (SecretKey) desCipher.unwrap(message.encrypteddata.get(1), "AES", Cipher.SECRET_KEY);

        Cipher desCipher2 = Cipher.getInstance("AES");
        desCipher2.init(Cipher.DECRYPT_MODE, sessionKey3);
        byte[] response = desCipher2.doFinal(message.encrypteddata.get(0));
        logging.append(localTime.now()+" Response is: " + new String(response) + "\n");
        logging.append(localTime.now()+" Finish Authorization Response Processing\n\n");

    }

    //Payment Capture Phase
    public void payementcapturerequest() throws IOException, ClassNotFoundException {
        message.clearvariables();
        //message for authorization
        logging.append(localTime.now()+" Start of Payment Capture Request\n");
        try {
            //generate sessionkey
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sessionkey = kgen.generateKey();

            Cipher desCipher;
            desCipher = Cipher.getInstance("AES");
            //encrypt using session key
            desCipher.init(Cipher.ENCRYPT_MODE, sessionkey);
            desCipher.update((numberFormat.format(order.getTotal()) + ":").getBytes());
            byte[] encrpyted1 = desCipher.doFinal(order.getTransaction_id().getBytes());

            desCipher = Cipher.getInstance("RSA");
            desCipher.init(Cipher.WRAP_MODE, bankcertificate.getPublicKey());
            byte[] wrappedsessionkey = desCipher.wrap(sessionkey);

            //Add encrypted amount+transactionid in ecrypteddata index 0
            //Add wrapped sessionkey into encrypteddata index 1
            message.encrypteddata.add(encrpyted1);
            message.encrypteddata.add(wrappedsessionkey);
            //send message
            message.certificates.add(merchantcertificate);
            b_os2.writeObject(message);
            logging.append(localTime.now()+" Sent the payment capture message\n");
            logging.append(localTime.now()+" Finish Payment Capture Request\n\n");
        } catch (Exception E) {

        }
    }

    public void processingofresponse() throws Exception {
        message.clearvariables();
        message = (RequestMessage) b_is2.readObject();

        logging.append(localTime.now()+ " Start of Payment Response Processing\n");

        try {
            Cipher desCipher = Cipher.getInstance("RSA");
            desCipher.init(Cipher.UNWRAP_MODE, keypair.getPrivateKey());

            SecretKey sessionKey3 = (SecretKey) desCipher.unwrap(message.encrypteddata.get(1), "AES", Cipher.SECRET_KEY);

            Cipher desCipher2 = Cipher.getInstance("AES");
            desCipher2.init(Cipher.DECRYPT_MODE, sessionKey3);
            byte[] response = desCipher2.doFinal(message.encrypteddata.get(0));
            logging.append(localTime.now()+" Payment Response is: " + new String(response) + "\n");
            logging.append(localTime.now()+ " Finish of Payment Response Processing\n\n");
            reset();
        } catch (Exception E) {

        }
    }
    
    public void reset(){
         while (true) {
             try {
                 String mes = c_is.readUTF();
                 if (mes.contains("Reset")) {
                     b_os2.writeUTF("Reset");
                     b_os2.flush();
                     logging.append("------------------------New Transaction -----------------------\n\n");
                     close_servers();
                     openclientserver();
                     connecttobank();
                     initiaterequest();
                     break;
                 }
             } catch (Exception ex) {
                 Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
             }
            }
    }

    private static X509Certificate createcertificate(CertAndKeyGen kgen) {
        X509Certificate certificate = null;
        try {
            //Generate self signed certificate
            certificate = kgen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 3600);
            //System.out.println("Certificate : " + certificate.toString());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | IOException | CertificateException | SignatureException ex) {
            ex.printStackTrace();
        }
        return certificate;
    }

    private static CertAndKeyGen generateKeypair() {
        CertAndKeyGen kpair = null;
        try {
            kpair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            kpair.generate(2048);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kpair;
    }

    public void close_servers() {
        try {
            //Close bank sockets
            b_os2.close();
            b_is2.close();
            Bank.close();

            // Close Client sockets
            c_os.close();
            c_is.close();
            clientSocket.close();
            MerchantServer.close();
            bank_connected = false;
            server_opened = false;
        } catch (IOException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
