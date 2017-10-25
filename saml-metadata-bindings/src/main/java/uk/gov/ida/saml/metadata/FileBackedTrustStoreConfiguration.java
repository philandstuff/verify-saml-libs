package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.security.KeyStore;

public class FileBackedTrustStoreConfiguration extends TrustStoreConfiguration {

    @NotNull
    @Valid
    @JsonProperty
    @JsonAlias({ "path" })
    private String trustStorePath;


    @Override
    public KeyStore getTrustStore() {
        return new KeyStoreLoader().load(trustStorePath, trustStorePassword);
    }
}
