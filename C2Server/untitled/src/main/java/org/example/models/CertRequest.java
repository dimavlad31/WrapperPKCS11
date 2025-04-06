package org.example.models;

public class CertRequest {

    // This field will hold the Base64-encoded certificate string
    private String certificate;

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }
}