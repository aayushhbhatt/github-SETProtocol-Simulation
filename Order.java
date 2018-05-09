/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package OrderInfo;

import java.text.DecimalFormat;
import java.util.ArrayList;

/**
 *
 * @author Alvin
 */
public class Order implements java.io.Serializable{
    private String transaction_id;
    private double tax=0, total=0;
    private double subtotal=0;
    private ArrayList <String> products = new ArrayList<>();
    private String Orderstatus, paymentstatus;

    public Order(String transaction_id) {
        this.transaction_id = transaction_id;
        Orderstatus = "Pending";
        paymentstatus = "Pending";
    }
    

    public String getTransaction_id() {
        return transaction_id;
    }

    public void setTransaction_id(String transaction_id) {
        this.transaction_id = transaction_id;
    }
    
    public void setproducts(ArrayList prod) {
        this.products = prod;
    }

    public double calculateTotal() {
        calculateTax();
        total = subtotal + tax;
        return  total;
    }

    public void calculateTax() {
        tax = subtotal * 0.13;
    }
    

    public double getSubtotal() {
        return subtotal;
    }
    public double getTax() {
        return tax;
    }
    
    public double getTotal() {
        return total;
    }

    public void setSubtotal(double subtotal) {
        this.subtotal = subtotal;
    }

    public String getOrderstatus() {
        return Orderstatus;
    }

    public void setOrderstatus(String Orderstatus) {
        this.Orderstatus = Orderstatus;
    }

    public String getPaymentstatus() {
        return paymentstatus;
    }

    public void setPaymentstatus(String paymentstatus) {
        this.paymentstatus = paymentstatus;
    }

    public ArrayList <String> getProducts() {
        return products;
    }

    public void addProducts(String product, int amount) {
        products.add(product);
        subtotal = subtotal+amount;
    }
    
    
}
