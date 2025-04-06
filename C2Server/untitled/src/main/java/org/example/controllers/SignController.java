package org.example.controllers;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.apache.commons.codec.binary.Hex;
import org.apache.coyote.RequestGroupInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.example.models.CertRequest;
import org.example.models.SignRequest;
import org.example.services.SignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.core.Converter;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sign")
public class SignController {

    private final SignService signService;
    private DSSDocument toSignDocument;
    private PAdESSignatureParameters parameters;
    private PAdESService padesService;
    private ToBeSigned dataToSign;
    private CertificateToken certificateToken;

    @Autowired
    public SignController(SignService signService) {
        this.signService = signService;
    }

    public static CertificateToken loadCertificateFromFile(String filePath) throws IOException, CertificateException {
        byte[] certBytes = Files.readAllBytes(new File(filePath).toPath());
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
        return new CertificateToken(x509Certificate);
    }
    private static final byte[] SHA256_DIGEST_INFO_PREFIX = {
            (byte)0x30, (byte)0x31,
            (byte)0x30, (byte)0x0D,
            (byte)0x06, (byte)0x09,
            (byte)0x60, (byte)0x86,
            (byte)0x48, (byte)0x01,
            (byte)0x65, (byte)0x03,
            (byte)0x04, (byte)0x02,
            (byte)0x01,
            (byte)0x05, (byte)0x00,
            (byte)0x04, (byte)0x20
    };

    private static byte[] buildSha256DigestInfo(byte[] sha256Raw) {
        if (sha256Raw.length != 32) {
            throw new IllegalArgumentException("SHA-256 ar trebui să aiba 32 octeti, are " + sha256Raw.length);
        }
        byte[] digestInfo = new byte[SHA256_DIGEST_INFO_PREFIX.length + sha256Raw.length];
        System.arraycopy(SHA256_DIGEST_INFO_PREFIX, 0, digestInfo, 0, SHA256_DIGEST_INFO_PREFIX.length);
        System.arraycopy(sha256Raw, 0, digestInfo, SHA256_DIGEST_INFO_PREFIX.length, sha256Raw.length);
        return digestInfo;
    }

    @GetMapping("/getHash")
    public ResponseEntity<Map<String, Object>> getHash() {
        try {

            this.toSignDocument = new FileDocument("C:\\Users\\Vlad\\Desktop\\Tavi.pdf");

            this.parameters = new PAdESSignatureParameters();
            this.parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

            this.certificateToken = loadCertificateFromFile("C:\\Users\\Vlad\\Desktop\\Cert_from_wrapper.raw");
            this.parameters.setSigningCertificate(certificateToken);
            this.parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            this.padesService = new PAdESService(certificateVerifier);

            this.dataToSign = padesService.getDataToSign(toSignDocument, this.parameters);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashSha256 = md.digest(dataToSign.getBytes());

            byte[] digestInfoSha256 = buildSha256DigestInfo(hashSha256);

            Digest digest = new Digest(DigestAlgorithm.SHA256, digestInfoSha256);


            Map<String, Object> response = new HashMap<>();
            response.put("hash", Base64.getEncoder().encodeToString(digest.getValue()));
            response.put("length", digest.getValue().length);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PostMapping("/addSign")
    public void addSign(@RequestBody SignRequest request) {
        try{

            byte[] signatureValueBytes = Base64.getDecoder().decode(request.getSignature());
            SignatureValue signatureValue = new SignatureValue(SignatureAlgorithm.RSA_SHA256, signatureValueBytes);


            DSSDocument signedDocument = this.padesService.signDocument(this.toSignDocument, this.parameters, signatureValue);


            try (FileOutputStream fos = new FileOutputStream("C:\\Users\\Vlad\\Desktop\\Tavi_signed_from_server.pdf")) {
                fos.write(DSSUtils.toByteArray(signedDocument));
            }



        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @PostMapping("/addCert")
    public ResponseEntity<Void> addCert(@RequestBody CertRequest request) {

        File outputFile = new File("C:\\Users\\Vlad\\Desktop\\Cert_from_wrapper.raw");

        try {
            if (outputFile.exists()) {
                try (FileInputStream fis = new FileInputStream(outputFile)) {
                    CertificateFactory cfExist = CertificateFactory.getInstance("X.509");
                    X509Certificate existingX509 = (X509Certificate) cfExist.generateCertificate(fis);

                    return ResponseEntity.ok().build();
                } catch (Exception e) {
                    outputFile.delete();
                }
            }

            byte[] certBytes = Base64.getDecoder().decode(request.getCertificate());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

            System.out.println("Received X.509 certificate:");
            System.out.println("Subject DN: " + x509.getSubjectDN());
            System.out.println("Issuer DN : " + x509.getIssuerDN());

            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(certBytes);
            }

            return ResponseEntity.ok().build();

        } catch (Exception e) {

            return ResponseEntity.badRequest().build();
        }
    }

}
