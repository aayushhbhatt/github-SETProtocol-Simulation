/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package OrderInfo;

/**
 *
 * @author Alvin
 */
public class Payment implements java.io.Serializable{
    private String credicardnumber;
    private String type;
    private String cvv;
    private String name;
    private String address;
    private double authorizeammount=0;
    private String expirydate;
    private String paymentstatus;
    
    public Payment(String credicardnumber, String name, String address, String type, String cvv) {
        this.credicardnumber = credicardnumber;
        this.name = name;
        this.address = address;
        paymentstatus = "Pending";
        this.type = type;
        this.cvv=cvv;
    }

    public void setCredicardnumber(String credicardnumber) {
        this.credicardnumber = credicardnumber;
    }

    public void setCvv(String cvv) {
        this.cvv = cvv;
    }


    public void setFname(String name) {
        this.name = name;
    }

    public void setAddress(String address) {
        this.address = address;
    }


    public double getAuthorizeammount() {
        return authorizeammount;
    }


    public void setAuthorizeammount(double authorizeammount) {
        this.authorizeammount = authorizeammount;
    }

    public String getname() {
        return name;
    }

    public String getAddress() {
        return address;
    }

    public String getExpirydate() {
        return expirydate;
    }

    public void setExpirydate(String expirydate) {
        this.expirydate = expirydate;
    }

    public String getPaymentstatus() {
        return paymentstatus;
    }

    public void setPaymentstatus(String paymentstatus) {
        this.paymentstatus = paymentstatus;
    }
    
    
}
