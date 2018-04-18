package uk.gov.ida.saml.metadata;

import certificates.values.CACertificates;
import keystore.KeyStoreRule;
import keystore.builders.KeyStoreRuleBuilder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.io.IOUtils;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;
import uk.gov.ida.common.shared.security.verification.PKIXParametersProvider;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntityDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(OpenSAMLMockitoRunner.class)
public class CertificateChainValidationFilterTest {

    private static final List<String> IDP_ENTITY_IDS = asList(TestEntityIds.STUB_IDP_ONE, TestEntityIds.STUB_IDP_TWO, TestEntityIds.STUB_IDP_THREE, TestEntityIds.STUB_IDP_FOUR);
    private static final List<String> HUB_ENTITY_IDS = Collections.singletonList(TestEntityIds.HUB_ENTITY_ID);

    @ClassRule
    public static KeyStoreRule idpKeyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().withCertificate("idp", CACertificates.TEST_IDP_CA)
                                                                    .withCertificate("root", CACertificates.TEST_ROOT_CA).build();

    @ClassRule
    public static KeyStoreRule hubKeyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().withCertificate("hub", CACertificates.TEST_CORE_CA)
                                                                    .withCertificate("root", CACertificates.TEST_ROOT_CA).build();

    @ClassRule
    public static KeyStoreRule rpKeyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().withCertificate("rp", CACertificates.TEST_RP_CA)
                                                                   .withCertificate("root", CACertificates.TEST_ROOT_CA).build();

    private MetadataFactory metadataFactory = new MetadataFactory();
    private CertificateChainValidator certificateChainValidator = new CertificateChainValidator(new PKIXParametersProvider(), new X509CertificateFactory());

    @Test
    public void shouldNotFilterOutTrustedCertificatesWhenAllCertificatesAreValid() throws Exception {
        final CertificateChainValidationFilter spCertificateChainValidationFilter = new CertificateChainValidationFilter(SPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, hubKeyStoreRule.getKeyStore());
        final CertificateChainValidationFilter idpCertificateChainValidationFilter = new CertificateChainValidationFilter(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, idpKeyStoreRule.getKeyStore());

        XMLObject metadata = validateMetadata(spCertificateChainValidationFilter, metadataFactory.defaultMetadata());
        metadata = idpCertificateChainValidationFilter.filter(metadata);

        assertThat(getEntityIdsFromMetadata(metadata, SPSSODescriptor.DEFAULT_ELEMENT_NAME)).containsOnlyElementsOf(HUB_ENTITY_IDS);
        assertThat(getEntityIdsFromMetadata(metadata, IDPSSODescriptor.DEFAULT_ELEMENT_NAME)).containsOnlyElementsOf(IDP_ENTITY_IDS);
    }

    @Test
    public void shouldReturnNullWhenMetadataIsEmpty() throws Exception {
        final CertificateChainValidationFilter spCertificateChainValidationFilter = new CertificateChainValidationFilter(SPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, hubKeyStoreRule.getKeyStore());
        final CertificateChainValidationFilter idpCertificateChainValidationFilter = new CertificateChainValidationFilter(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, idpKeyStoreRule.getKeyStore());

        XMLObject metadata = validateMetadata(spCertificateChainValidationFilter, metadataFactory.emptyMetadata());
        metadata = idpCertificateChainValidationFilter.filter(metadata);

        assertThat(metadata).isNull();
    }

    @Test
    public void shouldFilterOutUntrustedIdpCertificatesWhenAllIdpCertificatesAreNotSignedByCorrectCA() throws Exception {
        final CertificateChainValidationFilter certificateChainValidationFilter = new CertificateChainValidationFilter(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, hubKeyStoreRule.getKeyStore());

        final XMLObject metadata = validateMetadata(certificateChainValidationFilter, metadataFactory.defaultMetadata());

        assertThat(getEntityIdsFromMetadata(metadata, SPSSODescriptor.DEFAULT_ELEMENT_NAME)).containsOnlyElementsOf(HUB_ENTITY_IDS);
        assertThat(getEntityIdsFromMetadata(metadata, IDPSSODescriptor.DEFAULT_ELEMENT_NAME)).isEmpty();
    }

    @Test
    public void shouldFilterOutUntrustedHubCertificatesWhenAllHubCertificatesAreNotSignedByCorrectCA() throws Exception {
        final CertificateChainValidationFilter certificateChainValidationFilter = new CertificateChainValidationFilter(SPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, idpKeyStoreRule.getKeyStore());

        final XMLObject metadata = validateMetadata(certificateChainValidationFilter, metadataFactory.defaultMetadata());

        assertThat(getEntityIdsFromMetadata(metadata, SPSSODescriptor.DEFAULT_ELEMENT_NAME)).isEmpty();
        assertThat(getEntityIdsFromMetadata(metadata, IDPSSODescriptor.DEFAULT_ELEMENT_NAME)).containsOnlyElementsOf(IDP_ENTITY_IDS);
    }

    @Test
    public void shouldReturnNullWhenAllCertificatesAreNotSignedByCorrectCA() throws Exception {
        final CertificateChainValidationFilter spCertificateChainValidationFilter = new CertificateChainValidationFilter(SPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, rpKeyStoreRule.getKeyStore());
        final CertificateChainValidationFilter idpCertificateChainValidationFilter = new CertificateChainValidationFilter(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, rpKeyStoreRule.getKeyStore());

        XMLObject metadata = validateMetadata(spCertificateChainValidationFilter, metadataFactory.defaultMetadata());
        metadata = idpCertificateChainValidationFilter.filter(metadata);

        assertThat(metadata).isNull();
    }

    @Test
    public void shouldFilterOutUntrustedIdpCertificateWhenOneIdpCertificateIsNotSignedByCorrectCA() throws Exception {
        final CertificateChainValidationFilter certificateChainValidationFilter = new CertificateChainValidationFilter(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, certificateChainValidator, idpKeyStoreRule.getKeyStore());
        final EntityDescriptorFactory entityDescriptorFactory =  new EntityDescriptorFactory();
        String metadataWithOneBadIdpCertificate = metadataFactory.metadata(
            asList(
                entityDescriptorFactory.hubEntityDescriptor(),
                entityDescriptorFactory.idpEntityDescriptor(TestEntityIds.STUB_IDP_ONE),
                entityDescriptorFactory.idpEntityDescriptor(TestEntityIds.STUB_IDP_TWO),
                entityDescriptorFactory.idpEntityDescriptor(TestEntityIds.STUB_IDP_THREE),
                entityDescriptorFactory.idpEntityDescriptor(TestEntityIds.STUB_IDP_FOUR),
                entityDescriptorFactory.idpEntityDescriptor(TestEntityIds.TEST_RP)));

        final XMLObject metadata = validateMetadata(certificateChainValidationFilter, metadataWithOneBadIdpCertificate);

        assertThat(getEntityIdsFromMetadata(metadata, SPSSODescriptor.DEFAULT_ELEMENT_NAME)).containsOnlyElementsOf(HUB_ENTITY_IDS);
        assertThat(getEntityIdsFromMetadata(metadata, IDPSSODescriptor.DEFAULT_ELEMENT_NAME)).containsOnlyElementsOf(IDP_ENTITY_IDS);
    }

    private XMLObject validateMetadata(final CertificateChainValidationFilter certificateChainValidationFilter, String metadataContent) throws XMLParserException, UnmarshallingException, ComponentInitializationException {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.initialize();
        XMLObject metadata = XMLObjectSupport.unmarshallFromInputStream(parserPool, IOUtils.toInputStream(metadataContent));
        return certificateChainValidationFilter.filter(metadata);
    }

    private List<String> getEntityIdsFromMetadata(final XMLObject metadata, final QName role) {
        List<String> entityIds = new ArrayList<>();
        if (metadata != null) {
            final EntitiesDescriptor entitiesDescriptor = (EntitiesDescriptor) metadata;

            entitiesDescriptor.getEntityDescriptors().forEach(entityDescriptor -> {
                final String entityID = entityDescriptor.getEntityID();
                entityDescriptor.getRoleDescriptors().stream().filter(roleDescriptor -> roleDescriptor.getElementQName().equals(role)).map(roleDescriptor -> entityID).forEach(entityIds::add);
            });
        }
        return entityIds;
    }
}
