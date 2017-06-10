package implementation;

/**
 * Created by rols on 4/26/17.
 */

import code.GuiException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;
import sun.security.provider.DSAPublicKey;
import sun.security.provider.DSAPublicKeyImpl;
import x509.v3.CodeV3;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.DSAParameterSpec;
import java.util.*;

public class MyCode  extends CodeV3{

    private KeyStore myKeyStore;
    private X509Certificate rootCertificate;
    private KeyPair rootKeyPair;
    //private X509Certificate currentlySelectedCertificate;
    private String currentlySelected;

    private static String keyStoreFile;
    private static char[] keyStorePass;

    static {
        Security.addProvider(new BouncyCastleProvider());

        keyStoreFile = "myLocalKeyStore";
        keyStorePass = "javolimzp".toCharArray();
    }

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException, KeyStoreException {
        super(algorithm_conf, extensions_conf);

        initRootCertificate();
        currentlySelected = null;
    }

    private void initRootCertificate() {
        try {
            rootKeyPair = Helper.generateDSAKeypair(512);

        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }



    public static void main(String args[]) {
        System.out.println("testing!");

    }

    private void loadOrCreateLocalKeystore() {
        if (myKeyStore == null) {
            try {
                    myKeyStore  = KeyStore.getInstance(KeyStore.getDefaultType());

                    FileInputStream fs = null;
                    try {
                        fs = new FileInputStream(keyStoreFile);
                        myKeyStore.load(fs, keyStorePass);
                    } catch (FileNotFoundException e) {
                        //e.printStackTrace();
                        System.out.println("Local keystore file not found! meeeh, creating a new one");
                        myKeyStore.load(null, keyStorePass);
                        saveKeystore();
                    }

                    if (fs != null) {
                        fs.close();
                    }
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void saveKeystore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        FileOutputStream fos = new FileOutputStream(keyStoreFile);
        myKeyStore.store(fos, keyStorePass);
        fos.close();
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            loadOrCreateLocalKeystore();
            return myKeyStore.aliases();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void resetLocalKeystore() {

        try {
            myKeyStore.load(null, keyStorePass);
            saveKeystore();
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    @Override
    public int loadKeypair(String s) {
        try {
            X509Certificate cert = (X509Certificate) myKeyStore.getCertificateChain(s)[0];

            currentlySelected = s;

            Integer keySize;

            if (cert.getPublicKey() instanceof BCDSAPublicKey) {
                keySize = ((BCDSAPublicKey) cert.getPublicKey()).getY().bitLength();
            } else if (cert.getPublicKey() instanceof DSAPublicKeyImpl) {
                keySize = ((DSAPublicKeyImpl) cert.getPublicKey()).getY().bitLength();
            } else {
                throw new UnknownError();
            }

            JcaX509CertificateHolder nekiholder = new JcaX509CertificateHolder(cert);
            X500Name subject = nekiholder.getSubject();
//            RDN subjectc = subject.getRDNs(BCStyle.C)[0];
//            String subjectcountry = IETFUtils.valueToString(subjectc.getFirst().getValue());
//            RDN subjectst = subject.getRDNs(BCStyle.ST)[0];
//            String subjectstate = IETFUtils.valueToString(subjectst.getFirst().getValue());
//            RDN subjectl = subject.getRDNs(BCStyle.L)[0];
//            String subjectlocality = IETFUtils.valueToString(subjectl.getFirst().getValue());
//            RDN subjecto = subject.getRDNs(BCStyle.O)[0];
//            String subjectorganisation = IETFUtils.valueToString(subjecto.getFirst().getValue());
//            RDN subjectou = subject.getRDNs(BCStyle.OU)[0];
//            String subjectorganisationUnit = IETFUtils.valueToString(subjectou.getFirst().getValue());
//            RDN subjectcn = subject.getRDNs(BCStyle.CN)[0];
//            String subjectsubjectName = IETFUtils.valueToString(subjectcn.getFirst().getValue());

            X500Name issuer = nekiholder.getIssuer();
//            RDN issuerc = issuer.getRDNs(BCStyle.C)[0];
//            String issuercountry = IETFUtils.valueToString(issuerc.getFirst().getValue());
//            RDN issuerst = issuer.getRDNs(BCStyle.ST)[0];
//            String issuerstate = IETFUtils.valueToString(issuerst.getFirst().getValue());
//            RDN issuerl = issuer.getRDNs(BCStyle.L)[0];
//            String issuerlocality = IETFUtils.valueToString(issuerl.getFirst().getValue());
//            RDN issuero = issuer.getRDNs(BCStyle.O)[0];
//            String issuerorganisation = IETFUtils.valueToString(issuero.getFirst().getValue());
//            RDN issuerou = issuer.getRDNs(BCStyle.OU)[0];
//            String issuerorganisationUnit = IETFUtils.valueToString(issuerou.getFirst().getValue());
//            RDN issuercn = issuer.getRDNs(BCStyle.CN)[0];
//            String issuersubjectName = IETFUtils.valueToString(issuercn.getFirst().getValue());


            access.setPublicKeyParameter(String.valueOf(keySize));
            access.setPublicKeyAlgorithm("DSA"); // always the same ?
            access.setSerialNumber(String.valueOf(nekiholder.getSerialNumber()));

//            access.setSubjectCountry(subjectcountry);
//            access.setSubjectState(subjectstate);
//            access.setSubjectLocality(subjectlocality);
//            access.setSubjectOrganization(subjectorganisation);
//            access.setSubjectOrganizationUnit(subjectorganisationUnit);
//            access.setSubjectCommonName(subjectsubjectName);
            access.setSubject(subject.toString());
            access.setSubjectSignatureAlgorithm("SHA1withDSA"); // hardcoded!

            access.setIssuer(issuer.toString());
            access.setIssuerSignatureAlgorithm("SHA1withDSA");

            access.setNotBefore(nekiholder.getNotBefore());
            access.setNotAfter(nekiholder.getNotAfter());

            access.setVersion(cert.getVersion()==3?2:1);

        } catch (KeyStoreException | CertificateEncodingException e) {
            e.printStackTrace();
            return -1;
        }

        return 0;
    }

    @Override
    public boolean saveKeypair(String s) {

        try {

            if (access.getPublicKeyAlgorithm() != "DSA") {
                throw new NotImplementedException();
            }

            Integer keySize = Integer.parseInt(access.getPublicKeyParameter());
            KeyPair keypair = Helper.generateDSAKeypair(keySize);

            String signatureAlgorithm = access.getPublicKeySignatureAlgorithm();
            String serialNumber = access.getSerialNumber();
            X500Principal principal = Helper.getPrincipal(
                    access.getSubjectCountry(),
                    access.getSubjectState(),
                    access.getSubjectLocality(),
                    access.getSubjectOrganization(),
                    access.getSubjectOrganizationUnit(),
                    access.getSubjectCommonName());

            Date dateFrom = access.getNotBefore();
            Date dateTo = access.getNotAfter();

            X509Certificate[] certChain = new X509Certificate[1];

            X509Certificate cert = Helper.generateCertificate(
                    keypair,
                    serialNumber,
                    principal,
                    dateFrom,
                    dateTo,
                    principal,
                    signatureAlgorithm,
                    access.isCA());

            certChain[0] = cert;

            myKeyStore.setEntry(s,
                    new KeyStore.PrivateKeyEntry(keypair.getPrivate(), certChain),
                    new KeyStore.PasswordProtection(keyStorePass));

            saveKeystore();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException | CertificateException | KeyStoreException | IOException e) {
            e.printStackTrace();
        }

        return true;
    }

    @Override
    public boolean removeKeypair(String s) {

        try {
            myKeyStore.deleteEntry(s);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
        currentlySelected = null;

        return true;
    }

    @Override
    public boolean importKeypair(String keypairAlias, String filename, String password) {

        try {
            KeyStore keystore =  KeyStore.getInstance("PKCS12", "BC");

            FileInputStream fs = null;
            try {
                fs = new FileInputStream(filename);
                keystore.load(fs, password.toCharArray());

                String onlyKey = keystore.aliases().nextElement();

                KeyPair keyPair = new KeyPair(keystore.getCertificate(onlyKey).getPublicKey(), (PrivateKey)keystore.getKey(onlyKey, password.toCharArray()));

                myKeyStore.setEntry(
                        keypairAlias,
                        keystore.getEntry(
                                onlyKey,
                                new KeyStore.PasswordProtection(password.toCharArray())
                        ),
                        new KeyStore.PasswordProtection(keyStorePass)
                );

                saveKeystore();

            } catch (FileNotFoundException e) {
                //e.printStackTrace();
                return false;
            }

            if (fs != null) {
                fs.close();
            }

        } catch (KeyStoreException | NoSuchProviderException | CertificateException | NoSuchAlgorithmException | IOException |  UnrecoverableEntryException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    @Override
    public boolean exportKeypair(String keypairAlias, String filename, String password) {

        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");

            keystore.load(null, password.toCharArray());

            keystore.setEntry(
                    keypairAlias,
                    myKeyStore.getEntry(
                            keypairAlias,
                            new KeyStore.PasswordProtection(keyStorePass)
                    ),
                    new KeyStore.PasswordProtection(password.toCharArray())
            );

            FileOutputStream fos = new FileOutputStream(filename);
            keystore.store(fos, password.toCharArray());
            fos.close();

            return true;

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        }


        return false;
    }

    private KeyPair getKeyPair(String alias) {
        try {
            PrivateKey privKey = (PrivateKey) myKeyStore.getKey(alias, keyStorePass);
            PublicKey publicKey = myKeyStore.getCertificateChain(alias)[0].getPublicKey();

            return new KeyPair(publicKey, privKey);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public boolean signCertificate(String issuerAlias, String algorithm) {

        try {
            // issuer
            PrivateKey issuerPrivateKey = (PrivateKey)myKeyStore.getKey(issuerAlias, keyStorePass);
            X509Certificate issuerCertChain[] = (X509Certificate[]) myKeyStore.getCertificateChain(issuerAlias);
            JcaX509CertificateHolder issuerCertificateHolder = new JcaX509CertificateHolder(issuerCertChain[0]);
            X500Name issuer = issuerCertificateHolder.getSubject();

            // subject
            KeyPair subjectOriginalKeypair = getKeyPair(currentlySelected);
            X509Certificate subjectCertificate = (X509Certificate) myKeyStore.getCertificateChain(currentlySelected)[0];

            JcaX509CertificateHolder subjectCertificateHolder = new JcaX509CertificateHolder(subjectCertificate);
            X500Name subject = subjectCertificateHolder.getSubject();

            BigInteger serialNumber = subjectCertificateHolder.getSerialNumber();

            Date dateFrom = subjectCertificateHolder.getNotBefore();
            Date dateTo = subjectCertificateHolder.getNotAfter();

            KeyPair keyPairForSigning = new KeyPair(subjectOriginalKeypair.getPublic(), issuerPrivateKey);

            X509Certificate signedCert = Helper.generateCertificate(keyPairForSigning, serialNumber.toString(), subject, dateFrom, dateTo, issuer, algorithm);

            X509Certificate[] subjectCertificateChain = new X509Certificate[1 + issuerCertChain.length];
            subjectCertificateChain[0] = signedCert;
            for (int i = 0 ; i < issuerCertChain.length; i++) {
                subjectCertificateChain[i+1] = issuerCertChain[i];
            }

            myKeyStore.deleteEntry(currentlySelected);

            myKeyStore.setEntry(currentlySelected,
                    new KeyStore.PrivateKeyEntry(subjectOriginalKeypair.getPrivate(), subjectCertificateChain),
                    new KeyStore.PasswordProtection(keyStorePass));

            saveKeystore();

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }


        return true;
    }

    @Override
    public boolean importCertificate(File file, String s) {
        return false;
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        return false;
    }

    @Override
    public String getIssuer(String s) {
        return null;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String s) {
        return null;
    }

    @Override
    public int getRSAKeyLength(String s) {
        return 0;
    }

    @Override
    public List<String> getIssuers(String s) {

        List<String> issuers = new ArrayList<>();

        try {
            Enumeration<String> aliases = myKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                X509Certificate certificate = (X509Certificate)myKeyStore.getCertificateChain(alias)[0];

                if (Helper.isCertificateAuthority(certificate)) {
                    issuers.add(alias);
                }
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return issuers;
    }

    @Override
    public boolean generateCSR(String s) {



        // create a SubjectAlternativeName extension value
//        GeneralNames subjectAltName = new GeneralNames(
//                new GeneralName(GeneralName.rfc822Name, "test@test.test"));
        // create the extensions object and add it as an attribute
//        Vector oids = new Vector();
//        Vector values = new Vector();
//        oids.add(X509Extensions.SubjectAlternativeName);
//        values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
//        X509Extensions extensions = new X509Extensions(oids, values);
//        Attribute attribute = new Attribute(
//                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
//                new DERSet(extensions));
//
//        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
//                new X500Principal("CN=Requested Test Certificate"), pair.getPublic());
//        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
//        ContentSigner signer = csBuilder.build(pair.getPrivate());
//        PKCS10CertificationRequest csr = p10Builder.build(signer);
//        p10Builder.setAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
//                new DERSet(extensions) );

//        return csr;

        return true;

    }
}
