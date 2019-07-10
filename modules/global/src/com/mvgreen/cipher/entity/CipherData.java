package com.mvgreen.cipher.entity;

import com.haulmont.chile.core.annotations.MetaClass;
import com.haulmont.chile.core.annotations.MetaProperty;
import com.haulmont.chile.core.annotations.NamePattern;
import com.haulmont.cuba.core.entity.BaseIntegerIdEntity;

@NamePattern("%s|firstname,lastname,company")
@MetaClass(name = "cipher_CipherData")
public class CipherData extends BaseIntegerIdEntity {
    private static final long serialVersionUID = -4060928792300354245L;

    @MetaProperty
    protected String firstname;

    @MetaProperty
    protected String lastname;

    @MetaProperty
    protected String company;

    @MetaProperty
    protected byte[] privateKey;

    @MetaProperty
    protected byte[] publicKey;

    @MetaProperty
    protected byte[] encrypted;

    public byte[] getEncrypted() {
        return encrypted;
    }

    public void setEncrypted(byte[] encrypted) {
        this.encrypted = encrypted;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public String getCompany() {
        return company;
    }

    public void setCompany(String company) {
        this.company = company;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

}