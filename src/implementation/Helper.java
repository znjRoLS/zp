package implementation;

import jdk.nashorn.internal.runtime.regexp.joni.exception.ValueException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by rols on 6/10/17.
 */
public class Helper {

    private static final Integer[] dsaLengths = { 512, 576, 640, 704, 768, 832, 896, 960, 1024, 2048};

    public static KeyPair generateDSAKeypair(Integer length) throws NoSuchProviderException, NoSuchAlgorithmException, ValueException {

        if (!Arrays.asList(dsaLengths).contains(length)) {
            throw new ValueException("Not allowed dsa size!");
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");
        keyGen.initialize(length, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        return keyPair;
    }

    public static X509Certificate generateCertificate(
            KeyPair pair,
            String serialNumber,
            X500Principal issuerDN,
            Date from,
            Date to,
            X500Principal subjectDN,
            String signatureAlgorithm,
            boolean isCertificateAuthority
    ) throws SignatureException, NoSuchProviderException, InvalidKeyException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(new BigInteger(serialNumber));
        certGen.setIssuerDN(issuerDN);
        certGen.setNotBefore(from);
        certGen.setNotAfter(to);
        certGen.setSubjectDN(subjectDN);
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm(signatureAlgorithm);

        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCertificateAuthority));
//
//        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
//
//        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
//
//        certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }

    public static X509Certificate generateCertificate(
            KeyPair pair,
            String serialNumber,
            X500Name issuerDN,
            Date from,
            Date to,
            X500Name subjectDN,
            String signatureAlgorithm
    ) throws SignatureException, NoSuchProviderException, InvalidKeyException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();


        certGen.setSerialNumber(new BigInteger(serialNumber));
        certGen.setIssuerDN(new X500Principal(issuerDN.toString()));
        certGen.setNotBefore(from);
        certGen.setNotAfter(to);
        certGen.setSubjectDN(new X500Principal(subjectDN.toString()));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm(signatureAlgorithm);

//        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
//
//        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
//
//        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
//
//        certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }

    public static X500Principal getPrincipal(
            String country,
            String state,
            String locality,
            String organization,
            String organizationUnit,
            String commonName
    ) {
        StringBuilder sb = new StringBuilder();
        if (!country.equals("")) {
            sb.append("C=");
            sb.append(country);
            sb.append(",");
        }
        if (!state.equals("")) {
            sb.append("ST=");
            sb.append(state);
            sb.append(",");
        }
        if (!locality.equals("")) {
            sb.append("L=");
            sb.append(locality);
            sb.append(",");
        }
        if (!organization.equals("")) {
            sb.append("O=");
            sb.append(organization);
            sb.append(",");
        }
        if (!organizationUnit.equals("")) {
            sb.append("OU=");
            sb.append(organizationUnit);
            sb.append(",");
        }
        if (!commonName.equals("")) {
            sb.append("CN=");
            sb.append(commonName);
            sb.append(",");
        }

        sb.setLength(sb.length()-1);

        return new X500Principal(sb.toString());
    }

//    public static X509Certificate[] convertChain(Certificate[] chain) throws CertificateException {
//        X509Certificate newChain[] = new X509Certificate[chain.length];
//        for (int i = 0 ; i < chain.length; i++) {
//            X509Certificate newCert = (X509Certificate) chain[i];
//            newChain[i] = newCert;
//        }
//
//        return newChain;
//    }

//    public static boolean isCertificateAuthority(X509Certificate cert){
//        try {
//            byte[] basicConstraints=cert.getExtensionValue("2.5.29.19");
//            Object obj=new ASN1InputStream(basicConstraints).readObject();
//            basicConstraints=((DEROctetString)obj).getOctets();
//            obj=new ASN1InputStream(basicConstraints).readObject();
//            return BasicConstraints.getInstance((ASN1Sequence)obj).isCA();
//        }
//        catch (  Exception e) {
//            return false;
//        }
//    }
}
