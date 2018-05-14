package uk.gov.ida.saml.core.transformers;

import org.junit.Test;
import uk.gov.ida.saml.core.extensions.EidasAuthnContext;
import uk.gov.ida.saml.core.extensions.IdaAuthnContext;
import uk.gov.ida.saml.core.domain.AuthnContext;

import static java.text.MessageFormat.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

public class AuthnContextFactoryTest {

    private final AuthnContextFactory factory = new AuthnContextFactory();

    @Test
    public void shouldBeAbleToMapFromEidasToLoA() {
        assertThat(factory.mapFromEidasToLoA(EidasAuthnContext.EIDAS_LOA_LOW)).isEqualTo(AuthnContext.LEVEL_1);
        assertThat(factory.mapFromEidasToLoA(EidasAuthnContext.EIDAS_LOA_SUBSTANTIAL)).isEqualTo(AuthnContext.LEVEL_2);
        assertThat(factory.mapFromEidasToLoA(EidasAuthnContext.EIDAS_LOA_HIGH)).isEqualTo(AuthnContext.LEVEL_2);
    }

    @Test
    public void shouldThrowExceptionWhenMappingInvalidEidasToLoA() throws Exception {
        final String levelOfAssurance = "glarg";
        try {
            factory.mapFromEidasToLoA(levelOfAssurance);
            fail("fail");
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo(format(AuthnContextFactory.SAML_AUTHN_CONTEXT_IS_NOT_A_RECOGNISED_VALUE, levelOfAssurance));
        }
    }

    @Test
    public void transform_shouldCorrectlyTransformValidValues() throws Exception {
        assertThat(factory.authnContextForLevelOfAssurance(IdaAuthnContext.LEVEL_1_AUTHN_CTX)).isEqualTo(AuthnContext.LEVEL_1);
        assertThat(factory.authnContextForLevelOfAssurance(IdaAuthnContext.LEVEL_2_AUTHN_CTX)).isEqualTo(AuthnContext.LEVEL_2);
        assertThat(factory.authnContextForLevelOfAssurance(IdaAuthnContext.LEVEL_3_AUTHN_CTX)).isEqualTo(AuthnContext.LEVEL_3);
        assertThat(factory.authnContextForLevelOfAssurance(IdaAuthnContext.LEVEL_4_AUTHN_CTX)).isEqualTo(AuthnContext.LEVEL_4);
        assertThat(factory.authnContextForLevelOfAssurance(IdaAuthnContext.LEVEL_X_AUTHN_CTX)).isEqualTo(AuthnContext.LEVEL_X);
    }

    @Test
    public void transform_shouldThrowExceptionIfInvalidValue() throws Exception {
        final String levelOfAssurance = "glarg";
        try {
            factory.authnContextForLevelOfAssurance(levelOfAssurance);
            fail("fail");
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo(format(AuthnContextFactory.SAML_AUTHN_CONTEXT_IS_NOT_A_RECOGNISED_VALUE, levelOfAssurance));
        }
    }

}
