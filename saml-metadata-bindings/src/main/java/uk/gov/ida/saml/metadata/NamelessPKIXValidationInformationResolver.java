package uk.gov.ida.saml.metadata;

import java.util.Collections;
import java.util.List;

import org.opensaml.security.x509.PKIXValidationInformation;
import org.opensaml.security.x509.impl.StaticPKIXValidationInformationResolver;

public class NamelessPKIXValidationInformationResolver extends StaticPKIXValidationInformationResolver {

    public NamelessPKIXValidationInformationResolver(List<PKIXValidationInformation> info) {
        super(info, Collections.emptySet());
    }

    @Override
    public boolean supportsTrustedNameResolution() {
        return false;
    }
}
