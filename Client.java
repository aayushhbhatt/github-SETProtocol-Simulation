/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Components;

import OrderInfo.Order;
import OrderInfo.Payment;
import java.io.*;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
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
public class Client {

    JTextArea logging;
    Socket merchant = null;
    ObjectOutputStream os;
    ObjectInputStream is;
    String Username = null;
    int accountnumber;
    CertAndKeyGen keypair = generateKeypair();
    X509Certificate Client_certificate = createcertificate(keypair);
    X509Certificate Merchant_certificate;
    X509Certificate Bank_certificate;
    Order order;
    Payment creditcardinfo;
    byte[] orderdigest;
    byte[] paymentdigest;
    byte[] combinedMD;
    byte[] dualsignature;
    RequestMessage init = new RequestMessage();
    RequestMessage purchaserequest = new RequestMessage();
    Boolean server_connected = false;

    public Client(JTextArea textarea) {
        this.logging = textarea;
    }

    public void connecttomerchant() throws IOException {
        merchant = new Socket("127.0.0.1", 9999);
        os = new ObjectOutputStream(merchant.getOutputStream());
        is = new ObjectInputStream(merchant.getInputStream());
        server_connected = true;
        System.out.println("Merchant Connected");
    }

    public Order initiatetomerchant(String todo) {
        try {
            if (todo.contains("Check Balance")) {
                os.writeUTF(todo);
                os.flush();
                logging.append("Your Bank Balance is: ");
                logging.append(""+is.readDouble()+"\n");
            } else {
                os.writeUTF(" ");
                init.clearvariables();
                init.getInitStringMessage().add("Initiate");
                os.writeObject(init);
                init = (RequestMessage) is.readObject();

                //Initialize the correct variable from the recieved message
                order = new Order(init.InitStringMessage.get(0));
                Merchant_certificate = init.certificates.get(0);
                Bank_certificate = init.certificates.get(1);
                System.out.println("Order created with transaction id: " + order.getTransaction_id());
            }
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        return order;
    }

    // Creating the purchase message to send to merchant
    public void purchaserequest(Payment p) {
        this.creditcardinfo = p;
        purchaserequest.clearvariables();
        // Creates dual signature and pass the dual signature in index 0 of encrypteddata
        dualsignature();
        // Creates the encrypted payment for bank
        // Sealed Payment Object in the index 0 of sealedobject
        // Wrapped session key with bank public key in the index 1 of encrypted data
        encryptpaymentinfo();
        // Encrypting the order object and putting into index 1 of sealedobject
        // Wrapped session key with merchant public key in the index 2 of encrypted data
        encryptorderinfo();
        //Index 3 and 4 of encrypteddata will have orderdigest and paymentdigest
        purchaserequest.encrypteddata.add(orderdigest);
        purchaserequest.encrypteddata.add(paymentdigest);
//        StringBuffer hexString = new StringBuffer();
//        for (int i = 0; i < dualsignature.length; i++) {
//            hexString.append(Integer.toHexString(0xFF & dualsignature[i]));
//        }
        //Passing the client certificate in first index
        purchaserequest.certificates.add(Client_certificate);
        purchaserequest.InitStringMessage.add("Purchase Request");
        try {
            os.writeObject(purchaserequest);
            System.out.println(is.readUTF());
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void dualsignature() {
        try {
            MessageDigest duals = MessageDigest.getInstance("SHA-1");
            createOrderMD(); // Create Order MD
            createPaymentMD(); // Create Payment MD
            duals.update(orderdigest); // Update the message dist to include OIMD and PIMD
            duals.update(paymentdigest);
            combinedMD = duals.digest(); // Create the digest of the combined
            // Creating a digital signature 
            Signature dsign = Signature.getInstance("SHA1withRSA");
            dsign.initSign(keypair.getPrivateKey());
            dsign.update(combinedMD);
            dualsignature = dsign.sign();
            purchaserequest.encrypteddata.add(dualsignature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void encryptpaymentinfo() {
        try {
            //generate sessionkey
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sessionkey = kgen.generateKey();

            //encrypt using session key
            Cipher desCipher;
            desCipher = Cipher.getInstance("AES");
            desCipher.init(Cipher.ENCRYPT_MODE, sessionkey);
            SealedObject sealedpayment = new SealedObject(creditcardinfo, desCipher);
            purchaserequest.sealedobject.add(sealedpayment);

            Cipher desCipher2;
            desCipher2 = Cipher.getInstance("RSA");
            desCipher2.init(Cipher.WRAP_MODE, Bank_certificate.getPublicKey());
            byte[] wrappedsessionkey = desCipher2.wrap(sessionkey);
            purchaserequest.encrypteddata.add(wrappedsessionkey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | IOException | InvalidKeyException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void encryptorderinfo() {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sessionkey = kgen.generateKey();

            //encrypt using session key
            Cipher desCipher;
            desCipher = Cipher.getInstance("AES");
            desCipher.init(Cipher.ENCRYPT_MODE, sessionkey);
            SealedObject sealedorder = new SealedObject(order, desCipher);
            purchaserequest.sealedobject.add(sealedorder);

            Cipher desCipher2;
            desCipher2 = Cipher.getInstance("RSA");
            desCipher2.init(Cipher.WRAP_MODE, Merchant_certificate.getPublicKey());
            byte[] wrappedsessionkey = desCipher2.wrap(sessionkey);
            purchaserequest.encrypteddata.add(wrappedsessionkey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | IllegalBlockSizeException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void createOrderMD() {
        try {
            MessageDigest orderd = MessageDigest.getInstance("SHA-1");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(order);
            oos.close();
            orderd.update(baos.toByteArray());
            orderdigest = orderd.digest();
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void createPaymentMD() {
        try {
            MessageDigest paymentd = MessageDigest.getInstance("SHA-1");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(creditcardinfo);
            oos.close();
            paymentd.update(baos.toByteArray());
            paymentdigest = paymentd.digest();
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
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
        CertAndKeyGen kpair = null;
        try {
            kpair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            kpair.generate(2048);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kpair;
    }

    public void closeconnection() throws IOException {
        os.writeUTF("Reset");
        os.flush();
        os.close();
        is.close();
        merchant.close();
        server_connected = false;
    }
}
