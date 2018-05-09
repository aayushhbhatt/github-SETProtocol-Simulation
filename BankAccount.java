/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Components;

/**
 *
 * @author BHATT
 */
public class BankAccount {

    double accountId;
    double accountAmount;
    String Name;

    public BankAccount(double accountAmount, String name) {
        this.accountAmount = accountAmount;
        this.Name = name;
    }

    public double getAccountId() {
        return accountId;
    }

    public void setAccountId(double accountId) {
        this.accountId = accountId;
    }

    public double getAccountAmount() {
        return accountAmount;
    }

    public void setAccountAmount(double accountAmount) {
        this.accountAmount = accountAmount;
    }

    public String getName() {
        return Name;
    }

    public void setName(String name) {
        this.Name = name;
    }

    public String checkBalance(Double amount) {
        String result;
        if (amount < accountAmount) {
            result = "Valid";
        } else {
            System.out.println("Insufficent Funds");
            result = "Invalid";
        }
        return result;
    }

    public boolean debit(double amount) {
        boolean result;
        if (amount < accountAmount) {
            accountAmount = accountAmount - amount;
            result = true;
        } else {
            System.out.println("Insufficent Funds");
            result = false;
        }
        return result;
    }
    public void credit(double amount) {
            accountAmount = accountAmount + amount;
    }
    

}
