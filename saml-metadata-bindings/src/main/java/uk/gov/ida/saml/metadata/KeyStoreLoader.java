package uk.gov.ida.saml.metadata;

import com.google.common.base.Throwables;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class KeyStoreLoader {
    public KeyStore load(String uri, String password) {
        try {
            return load(new FileInputStream(uri), password);
        } catch (FileNotFoundException e) {
            throw Throwables.propagate(e);
        }
    }

    public KeyStore load(InputStream keystoreInputStream, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] charPassword = password.toCharArray();
            // Use a try with resource block to close the input stream once we've read it
            try (InputStream autoCloseableInputStream = keystoreInputStream) {
                keyStore.load(autoCloseableInputStream, charPassword);
            }
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw Throwables.propagate(e);
        }
    }
}
