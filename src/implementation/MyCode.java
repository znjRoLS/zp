package implementation;

/**
 * Created by rols on 4/26/17.
 */

import code.GuiException;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.DSAParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

public class MyCode  extends CodeV3{

    private KeyStore myKeyStore;
    private X509Certificate rootCertificate;
    private KeyPair rootKeyPair;

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
            RDN c = subject.getRDNs(BCStyle.C)[0];
            String country = IETFUtils.valueToString(c.getFirst().getValue());
            RDN st = subject.getRDNs(BCStyle.ST)[0];
            String state = IETFUtils.valueToString(st.getFirst().getValue());
            RDN l = subject.getRDNs(BCStyle.L)[0];
            String locality = IETFUtils.valueToString(l.getFirst().getValue());
            RDN o = subject.getRDNs(BCStyle.O)[0];
            String organisation = IETFUtils.valueToString(o.getFirst().getValue());
            RDN ou = subject.getRDNs(BCStyle.OU)[0];
            String organisationUnit = IETFUtils.valueToString(ou.getFirst().getValue());
            RDN cn = subject.getRDNs(BCStyle.CN)[0];
            String subjectName = IETFUtils.valueToString(cn.getFirst().getValue());


            access.setPublicKeyParameter(String.valueOf(keySize));
            access.setPublicKeyAlgorithm("DSA"); // always the same ?
            access.setSerialNumber(String.valueOf(nekiholder.getSerialNumber()));

            access.setSubjectCountry(country);
            access.setSubjectState(state);
            access.setSubjectLocality(locality);
            access.setSubjectOrganization(organisation);
            access.setSubjectOrganizationUnit(organisationUnit);
            access.setSubjectCommonName(subjectName);

            access.setNotBefore(nekiholder.getNotBefore());
            access.setNotAfter(nekiholder.getNotAfter());

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

            X509Certificate cert = Helper.generateSelfCertificate(keypair, serialNumber, principal, dateFrom, dateTo, principal, signatureAlgorithm);

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

    @Override
    public boolean signCertificate(String s, String s1) {
        return false;
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
        return null;
    }

    @Override
    public boolean generateCSR(String s) {
        return false;
    }
}
