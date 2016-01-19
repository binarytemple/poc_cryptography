package net.packetops;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

public class TryGeneratingx509v3Cert {

    public static void main(String[] args) throws Throwable {

//        LocalDateTime timePoint = LocalDateTime.now();
//        timePoint.toEpochSecond(ZoneOffset.UTC);
//
//        Long start = timePoint.toEpochSecond(ZoneOffset.UTC) * 1000;
//        Date startDate = new Date(start);
//        Date expiryDate = new Date(timePoint.plusYears(1).toEpochSecond(ZoneOffset.UTC) * 1000);
//
//
//        System.err.println(
//                "startDate: "  +  startDate + " \n" +
//                "expiryDate: "   +  expiryDate  + ""
//        );
//
//          BigInteger serialNumber = new BigInteger(start.toString());
//
//
//        SecureRandom random = new SecureRandom();
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//
//        generator.initialize(2048, random);
//
//        KeyPair pair = generator.generateKeyPair();
//        Key pubKey = pair.getPublic();
//
//        //PrivateKey caKey = new  ...;              // private key of the certifying authority (ca) certificate
////        X509Certificate caCert = ...;        // public key certificate of the certifying authority
//        KeyPair keyPair = pair;               // public/private key pair that we are creating certificate for
//        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder();
//        X500Principal subjectName = new X500Principal("CN=Test V3 Certificate");
////
////        certGen.setSerialNumber(serialNumber);
////        certGen.setIssuerDN(caCert.getSubjectX500Principal());
////        certGen.setNotBefore(startDate);
////        certGen.setNotAfter(expiryDate);
////        certGen.setSubjectDN(subjectName);
////        certGen.setPublicKey(keyPair.getPublic());
////        certGen.setSignatureAlgorithm(signatureAlgorithm);
////
////        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
////                new AuthorityKeyIdentifierStructure(caCert));
////        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
////                new SubjectKeyIdentifierStructure(keyPair.getPublic());
////
////        X509Certificate cert = certGen.generate(caKey, "BC");   // note: private key of CA

        generateAndSaveSelfSignedCertificate();

    }


    public static void generateAndSaveSelfSignedCertificate() throws Exception {
        SecureRandom random = new SecureRandom();

        DateTime now = DateTime.now();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Generate self-signed certificate
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        nameBuilder.addRDN(BCStyle.SURNAME, "hunt");
        nameBuilder.addRDN(BCStyle.GIVENNAME, "bryan");

        nameBuilder.addRDN(BCStyle.CN, "packetops.net");
        nameBuilder.addRDN(BCStyle.OU, "packetops.net");
        nameBuilder.addRDN(BCStyle.O, "packetops");
        nameBuilder.addRDN(BCStyle.CN, "packetops ca");
        nameBuilder.addRDN(BCStyle.C, "GB");
        nameBuilder.addRDN(BCStyle.ST, "London");
        nameBuilder.addRDN(BCStyle.L, "London");

        Date notBefore = now.minusMinutes(1).toDate();
        Date notAfter = now.plusYears(32).toDate();
        BigInteger serialNumber = new BigInteger(128, random);

        X509v3CertificateBuilder builder  =
                new JcaX509v3CertificateBuilder(nameBuilder.build(), serialNumber, notBefore, notAfter, nameBuilder.build(),
                        keyPair.getPublic());

//        builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, false, usage);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));




        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));




        certificate.checkValidity(now.toDate());
        certificate.verify(certificate.getPublicKey());


        System.err.println(certificate.toString());

        byte[] encoded = certificate.getEncoded();

        File certfile = new File("output.pem");

//        FileOutputStream fos;
//        fos = new FileOutputStream();
//
//        fos.write(encoded);

        JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(certfile));
        writer.writeObject(certificate);
        writer.close();



        //        File

        // certificate
        // keyPair.getPublic()
        // keyPair.getPrivate()

    }


}
