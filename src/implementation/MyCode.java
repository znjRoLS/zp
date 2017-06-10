package implementation;

/**
 * Created by rols on 4/26/17.
 */

import code.GuiException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.misc.BASE64Encoder;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;
import sun.security.provider.DSAPublicKeyImpl;
import sun.security.provider.X509Factory;
import sun.security.rsa.RSAPublicKeyImpl;
import x509.v3.CodeV3;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

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
                    myKeyStore  = KeyStore.getInstance("PKCS12", "BC");

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
            } catch (NoSuchProviderException e) {
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
            X509Certificate cert = (X509Certificate) myKeyStore.getCertificate(s);

            currentlySelected = s;

            Integer keySize;

            if (cert.getPublicKey() instanceof BCDSAPublicKey) {
                keySize = ((BCDSAPublicKey) cert.getPublicKey()).getY().bitLength();
            } else if (cert.getPublicKey() instanceof DSAPublicKeyImpl) {
                keySize = ((DSAPublicKeyImpl) cert.getPublicKey()).getY().bitLength();
            } else if (cert.getPublicKey() instanceof RSAPublicKeyImpl) {
                keySize = ((RSAPublicKeyImpl)cert.getPublicKey()).getPublicExponent().bitLength();
            } else if (cert.getPublicKey() instanceof BCRSAPublicKey) {
                keySize = ((BCRSAPublicKey)cert.getPublicKey()).getPublicExponent().bitLength();
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
            access.setPublicKeyAlgorithm("DSA"); // must be hardcoded
            access.setSerialNumber(String.valueOf(nekiholder.getSerialNumber()));

//            access.setSubjectCountry(subjectcountry);
//            access.setSubjectState(subjectstate);
//            access.setSubjectLocality(subjectlocality);
//            access.setSubjectOrganization(subjectorganisation);
//            access.setSubjectOrganizationUnit(subjectorganisationUnit);
//            access.setSubjectCommonName(subjectsubjectName);
            access.setSubject(subject.toString());
            access.setSubjectSignatureAlgorithm(cert.getSigAlgName());

            access.setIssuer(issuer.toString());
            access.setIssuerSignatureAlgorithm(cert.getSigAlgName());

            access.setNotBefore(nekiholder.getNotBefore());
            access.setNotAfter(nekiholder.getNotAfter());

            access.setVersion(cert.getVersion()==3?2:1);

            access.setCA(cert.getBasicConstraints() != -1);

            if (myKeyStore.isCertificateEntry(s)) {
                System.out.println("return 2");
                return 2;
            } else if (myKeyStore.getCertificateChain(s).length == 1) {
                System.out.println("return 0");
                return 0;
            } else {
                System.out.println("return 1");
                return 1;
            }

        } catch (KeyStoreException | CertificateEncodingException e) {
            e.printStackTrace();
            return -1;
        }
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

            //java.security.cert.Certificate[] certChain = new java.security.cert.Certificate[1];

            X509Certificate cert = Helper.generateCertificate(
                    keypair,
                    serialNumber,
                    principal,
                    dateFrom,
                    dateTo,
                    principal,
                    signatureAlgorithm,
                    access.isCA());

            //certChain[0] = new JcaX509CertificateConverter().getCertificate(new JcaX509CertificateHolder(cert));

//            myKeyStore.setEntry(s,
//                    new KeyStore.PrivateKeyEntry(keypair.getPrivate(), new java.security.cert.Certificate[]{cert}),
//                    new KeyStore.PasswordProtection(keyStorePass));

            //myKeyStore.setKeyEntry(s, keypair.getPrivate(), keyStorePass, new java.security.cert.Certificate[]{cert});
            myKeyStore.setEntry(
                    s,
                    new KeyStore.PrivateKeyEntry(
                            keypair.getPrivate(),
                            new java.security.cert.Certificate[]{cert}
                    ),
                    new KeyStore.PasswordProtection(
                            keyStorePass
                    )
            );

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
            saveKeystore();
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
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

                Enumeration<String> aliases = keystore.aliases();

                String onlyKey = aliases.nextElement();
                while(!keystore.isKeyEntry(onlyKey)) {
                    onlyKey = aliases.nextElement();
                }

                KeyPair keyPair = new KeyPair(keystore.getCertificate(onlyKey).getPublicKey(), (PrivateKey)keystore.getKey(onlyKey, password.toCharArray()));

//                myKeyStore.setEntry(
//                        keypairAlias,
//                        keystore.getEntry(
//                                onlyKey,
//                                new KeyStore.PasswordProtection(password.toCharArray())
//                        ),
//                        new KeyStore.PasswordProtection(keyStorePass)
//                );

                //myKeyStore.setKeyEntry(keypairAlias, keystore.getKey(onlyKey, password.toCharArray()), keyStorePass, keystore.getCertificateChain(onlyKey));
                myKeyStore.setEntry(
                        keypairAlias,
                        new KeyStore.PrivateKeyEntry(
                                (PrivateKey)keystore.getKey(onlyKey, password.toCharArray()),
                                keystore.getCertificateChain(onlyKey)
                        ),
                        new KeyStore.PasswordProtection(
                                keyStorePass
                        )
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

//            keystore.setEntry(
//                    keypairAlias,
//                    myKeyStore.getEntry(
//                            keypairAlias,
//                            new KeyStore.PasswordProtection(keyStorePass)
//                    ),
//                    new KeyStore.PasswordProtection(password.toCharArray())
//            );

            //keystore.setKeyEntry(keypairAlias, myKeyStore.getKey(keypairAlias, keyStorePass), password.toCharArray(), myKeyStore.getCertificateChain(keypairAlias));
            keystore.setEntry(
                    keypairAlias,
                    new KeyStore.PrivateKeyEntry(
                            (PrivateKey)myKeyStore.getKey(keypairAlias, keyStorePass),
                            myKeyStore.getCertificateChain(keypairAlias)
                    ),
                    new KeyStore.PasswordProtection(
                            password.toCharArray()
                    )
            );

            FileOutputStream fos = new FileOutputStream(filename);
            keystore.store(fos, password.toCharArray());
            fos.close();

            return true;

        } catch (KeyStoreException | NoSuchProviderException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException | CertificateException e) {
            e.printStackTrace();
            return false;
        }
    }

    private KeyPair getKeyPair(String alias) {
        try {
            PrivateKey privKey = (PrivateKey) myKeyStore.getKey(alias, keyStorePass);
            PublicKey publicKey = myKeyStore.getCertificate(alias).getPublicKey();

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
            System.out.println(issuerAlias);
            System.out.println(algorithm);

            // issuer
            PrivateKey issuerPrivateKey = (PrivateKey)myKeyStore.getKey(issuerAlias, keyStorePass);
            java.security.cert.Certificate issuerCertChain[] = myKeyStore.getCertificateChain(issuerAlias);
            JcaX509CertificateHolder issuerCertificateHolder = new JcaX509CertificateHolder((X509Certificate)issuerCertChain[0]);
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

            X509Certificate signedCert = Helper.generateCertificate(keyPairForSigning, serialNumber.toString(), issuer, dateFrom, dateTo, subject, algorithm);

            java.security.cert.Certificate[] subjectCertificateChain = new java.security.cert.Certificate[1 + issuerCertChain.length];

            subjectCertificateChain[0] = signedCert;
            for (int i = 0 ; i < issuerCertChain.length; i++) {
                subjectCertificateChain[i+1] = issuerCertChain[i];
            }

            myKeyStore.deleteEntry(currentlySelected);

//            myKeyStore.setEntry(currentlySelected,
//                    new KeyStore.PrivateKeyEntry(subjectOriginalKeypair.getPrivate(), subjectCertificateChain),
//                    new KeyStore.PasswordProtection(keyStorePass));

            System.out.println("sta " + subjectCertificateChain.length);
            //myKeyStore.setKeyEntry(currentlySelected, subjectOriginalKeypair.getPrivate(), keyStorePass, subjectCertificateChain);
            myKeyStore.setEntry(
                    currentlySelected,
                    new KeyStore.PrivateKeyEntry(
                            subjectOriginalKeypair.getPrivate(),
                            subjectCertificateChain
                    ),
                    new KeyStore.PasswordProtection(
                            keyStorePass
                    )
            );
            System.out.println("sta " + subjectCertificateChain.length);
            System.out.println("sta " + myKeyStore.getCertificateChain(currentlySelected).length);

            saveKeystore();

            return true;

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | IOException | CertificateException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean importCertificate(File file, String s) {

        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            FileInputStream fileInputStream = new FileInputStream(file);

            X509Certificate certificate = (X509Certificate)fact.generateCertificate(fileInputStream);

            //myKeyStore.setCertificateEntry(s, certificate);
            myKeyStore.setEntry(
                    s,
                    new KeyStore.TrustedCertificateEntry(
                            certificate
                    ),
                    new KeyStore.PasswordProtection(
                            keyStorePass
                    )
            );
            saveKeystore();
            return true;

        } catch (CertificateException | KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean exportCertificate(File file, int i) {

        try {
            java.security.cert.Certificate certificate = myKeyStore.getCertificate(currentlySelected);

            FileOutputStream out = new FileOutputStream(file);

            if (i == 1) {
                BASE64Encoder encoder = new BASE64Encoder();
                out.write(X509Factory.BEGIN_CERT.getBytes());
                out.write("\n".getBytes());
                encoder.encodeBuffer(certificate.getEncoded(), out);
                out.write(X509Factory.END_CERT.getBytes());
                out.write("\n".getBytes());
            } else {
                out.write(certificate.getEncoded());
            }

            out.close();

            return true;
        } catch (KeyStoreException | IOException | CertificateEncodingException e) {
            e.printStackTrace();
            return false;
        }

    }

    @Override
    public String getIssuer(String s) {
        try {
            X509Certificate certificate = (X509Certificate) myKeyStore.getCertificate(s);
            JcaX509CertificateHolder issuerCertificateHolder = new JcaX509CertificateHolder(certificate);
            X500Name issuer = issuerCertificateHolder.getSubject();

            System.out.println("issuer to string " + issuer.toString());

            return issuer.toString();
        } catch (CertificateEncodingException | KeyStoreException e) {
            e.printStackTrace();

            return null;
        }
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String s) {

        try {
            X509Certificate certificate = (X509Certificate)myKeyStore.getCertificate(s);

            return certificate.getPublicKey().getAlgorithm();

        } catch (KeyStoreException e) {
            e.printStackTrace();

            return null;
        }

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

                if (alias.equals(s)) continue;

                X509Certificate certificate = (X509Certificate)myKeyStore.getCertificate(alias);

                System.out.println("alias " + alias + " has bc " + certificate.getBasicConstraints());

                //if (Helper.isCertificateAuthority(certificate)) {
                if (certificate.getBasicConstraints() != -1) {
                    issuers.add(alias);
                }
            }
            return issuers;
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean generateCSR(String alias) {

        try {
            KeyPair keypair = getKeyPair(alias);

            JcaX509CertificateHolder issuerCertificateHolder = new JcaX509CertificateHolder((X509Certificate)myKeyStore.getCertificate(alias));
            X500Name issuer = issuerCertificateHolder.getSubject();

            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    issuer, keypair.getPublic());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA1withDSA");
            ContentSigner signer = csBuilder.build(keypair.getPrivate());
            PKCS10CertificationRequest csr = p10Builder.build(signer);

            return true;
        } catch (KeyStoreException | CertificateEncodingException | OperatorCreationException e) {
            e.printStackTrace();

            return false;
        }


    }
}
