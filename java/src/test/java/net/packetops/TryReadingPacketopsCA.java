package net.packetops;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.Iterator;
import java.security.Security;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class TryReadingPacketopsCA {

    public static void main(String[] args) throws Throwable {


        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());

        FileInputStream fileInputStream = getFileInputStream("packetopsca.crt");

        BouncyCastleProvider provider = (BouncyCastleProvider) certificateFactory.getProvider();

        System.err.println(provider.getClass());

        provider.load(fileInputStream);
        fileInputStream.close();

        // provider.list(new PrintStream(System.out, false));

//        Set<Provider.Service> services = provider.getServices();
//        for (Provider.Service ps : services) {
//            System.err.println(ps);
//        }


        FileInputStream fileInputStream2 = getFileInputStream("packetopsca.crt");


        Certificate certificate = certificateFactory.generateCertificate(fileInputStream2);

        System.err.println(certificate);

        fileInputStream2.close();

//        System.err.println(provider.getInfo());

//        System.err.println( "----- provider.propertyNames() ----- ");
//
//        Enumeration<?> enumeration = provider.propertyNames();
//        while (enumeration.hasMoreElements()) {
//            System.err.println(enumeration.nextElement());
//        }
//
//        System.out.println("TESt");
//        Iterator<String> certPathEncodings = certificateFactory.getCertPathEncodings();
//
//        while (certPathEncodings.hasNext()) {
//            System.err.println(certPathEncodings.next());
//        }


    }

    private static FileInputStream getFileInputStream(String name) throws FileNotFoundException {
        return new FileInputStream(name);
    }

}
