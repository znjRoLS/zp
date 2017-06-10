package implementation;

/**
 * Created by rols on 4/26/17.
 */

import code.GuiException;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;
import x509.v3.CodeV3;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.DSAParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

public class MyCode  extends CodeV3{
    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException, KeyStoreException {
        super(algorithm_conf, extensions_conf);
    }

    BigInteger p = new BigInteger("13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223");
    BigInteger q = new BigInteger("857393771208094202104259627990318636601332086981");
    BigInteger g = new BigInteger("5421644057436475141609648488325705128047428394380474376834667300766108262613900542681289080713724597310673074119355136085795982097390670890367185141189796");

    KeyStore myKeyStore;

    private static String keyStoreFile;
    private static char[] keyStorePass;

    static {
        keyStoreFile = "myLocalKeyStore";
        keyStorePass = "javolimzp".toCharArray();
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
        return;
    }

    @Override
    public int loadKeypair(String s) {

        return 0;
    }

    @Override
    public boolean saveKeypair(String s) {

        System.out.println("save?");
        System.out.println(s);

        System.out.println("key algo");
        System.out.println(access.getPublicKeyAlgorithm());
        System.out.println("key param");
        System.out.println(access.getPublicKeyParameter());
        System.out.println("key sig");
        System.out.println(access.getPublicKeySignatureAlgorithm());

        System.out.println(access.)


        try {

            if (access.getPublicKeyAlgorithm() != "DSA") {
                throw new NotImplementedException();
            }

            Integer keySize = Integer.parseInt(access.getPublicKeyParameter());
            KeyPair keypair = Helper.generateDSAKeypair(keySize);

            X509Certificate[] certChain = new X509Certificate[1];



//            // its always dsa, but nevermind
//            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(access.getPublicKeyAlgorithm());
//
//            DSAParameterSpec dsaSpec = new DSAParameterSpec(p, q, g);
//
//            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
//            // always 512, but nevermind
//            Integer keySize = Integer.parseInt(access.getPublicKeyParameter());
//            keyGen.initialize(keySize, random);
//
//            KeyPair pair = keyGen.generateKeyPair();
//
//            System.out.println(pair.toString());
//            System.out.println(new String(pair.getPrivate().getEncoded()));
//            System.out.println(new String(pair.getPublic().getEncoded()));
//
//            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//
//            X509Certificate[] serverChain = new X509Certificate[1];
//            X509V3CertificateGenerator serverCertGen = new X509V3CertificateGenerator();
//            X500Principal serverSubjectName = new X500Principal("CN=OrganizationName");
//            serverCertGen.setSerialNumber(new BigInteger("123456789"));
//// X509Certificate caCert=null;
//            serverCertGen.setIssuerDN(new X509Name("CN=somename"));
//            serverCertGen.setNotBefore(new Date());
//            serverCertGen.setNotAfter(new Date());
//            serverCertGen.setSubjectDN(new X509Name("DN=someothername"));
//            serverCertGen.setPublicKey(pair.getPublic());
//            serverCertGen.setSignatureAlgorithm(access.getPublicKeySignatureAlgorithm());
//// certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,new
//// AuthorityKeyIdentifierStructure(caCert));
//
//            serverChain[0] = serverCertGen.generateX509Certificate(pair.getPrivate(), "BC"); // note: private key of CA
//
//            myKeyStore.setEntry(s,
//                    new KeyStore.PrivateKeyEntry(pair.getPrivate(), serverChain),
//                    new KeyStore.PasswordProtection("".toCharArray()));
//
//            saveKeystore();

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        return true;
    }

    @Override
    public boolean removeKeypair(String s) {
        return false;
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
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
