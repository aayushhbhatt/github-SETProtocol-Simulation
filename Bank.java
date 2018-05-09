/**
 *
 * @author BHATT
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Components;

import static Components.Merchant.bankcertificate;
import OrderInfo.Payment;
import java.io.*;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalTime;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.swing.JTextArea;

/**
 *
 * @author Bhatt
 */
public class Bank {

    JTextArea logging;
    CertAndKeyGen kpair = generateKeypair();
    X509Certificate Bank_certificate = createcertificate(kpair);
    ServerSocket BankServer = null;
    Socket merchantSocket = null;
    ObjectInputStream is;
    ObjectOutputStream os;
    X509Certificate Merchant_certificate;
    X509Certificate Client_certificate;
    RequestMessage authorizationmessage = new RequestMessage();
    RequestMessage authorizationResponseMessage = new RequestMessage();
    RequestMessage paymentauthorizationMessage = new RequestMessage();
    RequestMessage paymentResponseMessage = new RequestMessage();
    Payment p;
    static boolean server_opened = false;
    BankAccount[] accounts = new BankAccount[3];
    BankAccount account1 = new BankAccount(1000, "Client");
    BankAccount account2 = new BankAccount(2000, "Merchant");
    LocalTime localTime;

    public Bank(JTextArea textarea) {
        this.logging = textarea;
        accounts[0] = account1;
        accounts[1] = account2;
    }

    public void openbankserver() throws Exception {
        if (server_opened == false) {
            BankServer = new ServerSocket(1000);
            merchantSocket = BankServer.accept();
            server_opened = true;
            logging.append(localTime.now()+" Merchant Connected\n\n");
            os = new ObjectOutputStream(merchantSocket.getOutputStream());
            is = new ObjectInputStream(merchantSocket.getInputStream());
            os.writeObject(Bank_certificate);
            inittoMerchant();
        } else {
            logging.append(localTime.now()+" Merchant has already connected...\n");
        }

    }

    public void inittoMerchant() throws Exception {
        if (is.readUTF().contains("Check Balance")) {
            try {
                os.writeDouble(account1.getAccountAmount());
                os.flush();
                logging.append("Client Check Balance: " + account1.getAccountAmount()+"\n\n");
                reset();
            } catch (IOException ex) {
                Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
        authorizationmessage.clearvariables();
        authorizationmessage = (RequestMessage) is.readObject();
        if (authorizationmessage.InitStringMessage.contains("Authorization Request")) {
            try {
                processAuthorizationRequest();
            } catch (Exception ex) {
                Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
            }
            processpayementCaptureRequest();
        }
        }
    }

    public void processAuthorizationRequest() throws Exception {
        logging.append(localTime.now()+" Start Authorization Request Details: \n");
        Client_certificate = authorizationmessage.certificates.get(0);
        Merchant_certificate = authorizationmessage.certificates.get(1);

        try {
            Cipher deCipher1 = Cipher.getInstance("RSA");
            deCipher1.init(Cipher.UNWRAP_MODE, kpair.getPrivateKey());
            Key sessionkey2;
            sessionkey2 = deCipher1.unwrap(authorizationmessage.encrypteddata.get(1), "AES", Cipher.SECRET_KEY);
            Cipher desCipher = Cipher.getInstance("AES");
            desCipher.init(Cipher.DECRYPT_MODE, sessionkey2);
            byte[] transactionid = desCipher.doFinal(authorizationmessage.encrypteddata.get(0));
            String[] message = new String(transactionid).split(":");
            logging.append(localTime.now()+" Transaction id: " + message[1] + " Amount: " + message[0] + "\n");
            //Decrypting the payment information from the client
            decryptingpaymentfromcustomer();
            logging.append(localTime.now()+" Finish Authorization Request\n\n");
        } catch (Exception ex) {
            Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
        }
        AuthorizationResponse();
    }

    //Sends string response "Valid" 
    //Wraps the reponse in with generated session key 
    //Encryptes session key using merchants publickey
    //Attaches request message to the  writeObject via Outstream object
    public void AuthorizationResponse() throws Exception {
        logging.append(localTime.now()+" Start Authorization Response \n");
        String result = "Invalid";
        if (p.getname().contains(accounts[0].getName())) {
            result = accounts[0].checkBalance(p.getAuthorizeammount());
        }
        authorizationResponseMessage.clearvariables();
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey sessionkey3 = kgen.generateKey();

        Cipher deCipher3 = Cipher.getInstance("AES");
        //encrypt using session key
        deCipher3.init(Cipher.ENCRYPT_MODE, sessionkey3);
        byte[] encrpyted1 = deCipher3.doFinal(result.getBytes());

        //Encrypt the sessionkey
        Cipher deCipher = Cipher.getInstance("RSA");
        deCipher.init(Cipher.WRAP_MODE, Merchant_certificate.getPublicKey());
        byte[] wrappedsessionkey3 = deCipher.wrap(sessionkey3);
        //Adds the encrypted message in index 0
        //Adds the wrapped session key in index 1
        authorizationResponseMessage.encrypteddata.add(encrpyted1);
        authorizationResponseMessage.encrypteddata.add(wrappedsessionkey3);
        //Adding the bank certificate in index 0
        authorizationResponseMessage.certificates.add(bankcertificate);
        os.writeObject(authorizationResponseMessage);  //sends authorization response to merchant with String message Valid 
        logging.append(localTime.now()+" Sent Respone to merchant\n");
        logging.append(localTime.now()+" Finish Authorization Response\n\n");
    }

    public void processpayementCaptureRequest() throws Exception {
        paymentauthorizationMessage.clearvariables();
        paymentauthorizationMessage = (RequestMessage) is.readObject();

        logging.append(localTime.now()+" Start of Payment Capture Processing\n");
        try {
            Cipher deCipher5 = Cipher.getInstance("RSA");
            deCipher5.init(Cipher.UNWRAP_MODE, kpair.getPrivateKey());
            SecretKey sessionKey4 = (SecretKey) deCipher5.unwrap(paymentauthorizationMessage.encrypteddata.get(1), "AES", Cipher.SECRET_KEY);

            Cipher deCipher1 = Cipher.getInstance("AES");
            deCipher1.init(Cipher.DECRYPT_MODE, sessionKey4);
            byte[] decrypted3 = deCipher1.doFinal(paymentauthorizationMessage.encrypteddata.get(0));

            String[] message = new String(decrypted3).split(":");
            logging.append(localTime.now()+" Transaction id: " + message[1] + " Amount: " + message[0] + "\n");
            logging.append(localTime.now()+" Finish of Payment Capture Processing\n\n");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
        }
        paymentCaptureResponse();
    }
//    

    public void paymentCaptureResponse() throws Exception {
        logging.append(localTime.now()+" Start of Payment Capture Response\n");
        Boolean result = false;
        String response = "Payment failed";
        if (p.getname().contains(accounts[0].getName())) {
            result = accounts[0].debit(p.getAuthorizeammount());
            if (result) {
                accounts[1].credit(p.getAuthorizeammount());
                response = "Payment correctly captured";
            } else {
                logging.append("Not enough funds in the client's bank");
            }
        }
        paymentResponseMessage.clearvariables();

        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey sessionkey5 = kgen.generateKey();

        Cipher deCipher6 = Cipher.getInstance("AES");

        //encrypt using session key
        deCipher6.init(Cipher.ENCRYPT_MODE, sessionkey5);
        byte[] encrpyted4 = deCipher6.doFinal(response.getBytes());

        Cipher deCipher7 = Cipher.getInstance("RSA");
        deCipher7.init(Cipher.WRAP_MODE, Merchant_certificate.getPublicKey());
        byte[] wrappedsessionkey5 = deCipher7.wrap(sessionkey5);
        //Add encrypted amount+transactionid in ecrypteddata index 0
        //Add wrapped sessionkey 2 into encrypteddata index 1
        paymentResponseMessage.encrypteddata.add(encrpyted4);
        paymentResponseMessage.encrypteddata.add(wrappedsessionkey5);
        paymentResponseMessage.certificates.add(bankcertificate);

        os.writeObject(paymentResponseMessage);
        os.flush();
        logging.append(localTime.now()+" Sent Payment Capture Response from Bank\n");
        logging.append(localTime.now()+" Finish Payment Capture Response\n\n");
        while (true) {
            if (reset() == false) {
                break;
            }
        }

    }

    public boolean reset() throws IOException {
        Boolean result = false;
        try {
            String mes = is.readUTF();
            if (mes.contains("Reset")) {
                logging.append("------------------------New Transaction -----------------------\n\n");
                closeconnection();
                openbankserver();
                inittoMerchant();
                result = true;
            }
        } catch (Exception ex) {
            Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
            //System.out.println("Error occured when checking for new order" + ex);
        }
        return result;
    }

    public X509Certificate createcertificate(CertAndKeyGen kgen) {
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

    public CertAndKeyGen generateKeypair() {
        try {
            kpair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            kpair.generate(1024);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kpair;
    }

    public void decryptingpaymentfromcustomer() throws IOException, ClassNotFoundException {
        SealedObject s_payment = authorizationmessage.sealedobject.get(0);
        try {
            //Decrypt the session key using own private key
            Cipher desCipher2 = Cipher.getInstance("RSA");
            Key sessionkey;
            desCipher2.init(Cipher.UNWRAP_MODE, kpair.getPrivateKey());
            sessionkey = desCipher2.unwrap(authorizationmessage.encrypteddata.get(2), "AES", Cipher.SECRET_KEY);

            // Decrypting the payment object using the unwrapped session key
            Cipher desCipher = Cipher.getInstance("AES");
            desCipher.init(Cipher.DECRYPT_MODE, sessionkey);
            p = (Payment) s_payment.getObject(desCipher);
            logging.append("Payment Details is: " + p.getname() + " " + p.getAddress());
            //checkCustomerAccountability();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public void closeconnection() throws IOException {
        os.close();
        is.close();
        merchantSocket.close();
        BankServer.close();
        server_opened = false;
    }
}
