package implementation;

import jdk.nashorn.internal.runtime.regexp.joni.exception.ValueException;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
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

    public static X509Certificate generateSelfCertificate(
            KeyPair pair,
            BigInteger serialNumber,
            String issuerDN,


    ) throws SignatureException, NoSuchProviderException, InvalidKeyException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }
}