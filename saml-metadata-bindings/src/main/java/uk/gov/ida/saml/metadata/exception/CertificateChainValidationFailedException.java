package uk.gov.ida.saml.metadata.exception;

public class CertificateChainValidationFailedException extends Exception {

    public CertificateChainValidationFailedException(final String message) {
        super(message);
    }
}
