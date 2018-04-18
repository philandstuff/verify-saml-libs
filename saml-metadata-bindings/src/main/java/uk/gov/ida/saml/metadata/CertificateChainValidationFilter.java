package uk.gov.ida.saml.metadata;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;
import uk.gov.ida.saml.metadata.exception.CertificateConversionException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;
import javax.xml.namespace.QName;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;

import static org.opensaml.xmlsec.keyinfo.KeyInfoSupport.getCertificates;

public final class CertificateChainValidationFilter implements MetadataFilter {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateChainValidationFilter.class);

    private final QName role;
    private final CertificateChainValidator certificateChainValidator;
    private final KeyStore keyStore;

    public CertificateChainValidationFilter(
        @NotNull final QName role,
        @NotNull final CertificateChainValidator certificateChainValidator,
        @NotNull final KeyStore keyStore) {

        this.role = role;
        this.certificateChainValidator = certificateChainValidator;
        this.keyStore = keyStore;
    }

    public QName getRole() {
        return role;
    }

    public CertificateChainValidator getCertificateChainValidator() {
        return certificateChainValidator;
    }

    private KeyStore getKeyStore() {
        return keyStore;
    }

    @Nullable
    @Override
    public XMLObject filter(@Nullable XMLObject metadata) {
        if (metadata == null) {
            return null;
        }

        try {
            if (metadata instanceof EntityDescriptor) {
                processEntityDescriptor((EntityDescriptor) metadata);
            } else if (metadata instanceof EntitiesDescriptor) {
                processEntityGroup((EntitiesDescriptor) metadata);
            } else {
                LOG.error("Internal error, metadata object was of an unsupported type: {}", metadata.getClass().getName());
            }
        } catch (Throwable t) {
            LOG.error("Saw fatal error validating certificate chain, metadata will be filtered out", t);
            return null;
        }

        return metadata;
    }

    private void processEntityDescriptor(@Nonnull EntityDescriptor entityDescriptor) throws FilterException {
        final String entityID = entityDescriptor.getEntityID();
        LOG.trace("Processing EntityDescriptor: {}", entityID);

        // Note that this is ok since we're iterating over an IndexedXMLObjectChildrenList directly,
        // rather than a sublist like in processEntityGroup, and iterator remove() is supported there.
        entityDescriptor.getRoleDescriptors()
            .removeIf(roleDescriptor -> {
                if (getRole().equals(roleDescriptor.getElementQName())) {
                    try {
                        performCertificateChainValidation(roleDescriptor);
                    } catch (final FilterException e) {
                        LOG.error("RoleDescriptor '{}' subordinate to entity '{}' failed certificate chain validation, " +
                                  "removing from metadata provider", roleDescriptor.getElementQName(), entityID);
                        return true;
                    }
                }
                return false;
            });

        if (entityDescriptor.getRoleDescriptors().isEmpty()) {
            throw new FilterException("Role Descriptors list is empty");
        }
    }

    private void processEntityGroup(@Nonnull EntitiesDescriptor entitiesDescriptor) throws FilterException {
        final String name = getGroupName(entitiesDescriptor);
        LOG.trace("Processing EntitiesDescriptor group: {}", name);

        // Can't use IndexedXMLObjectChildrenList sublist iterator remove() to remove members,
        // so just note them in a set and then remove after iteration has completed.
        final HashSet<XMLObject> toRemove = new HashSet<>();

        entitiesDescriptor.getEntityDescriptors().forEach(
            entityDescriptor -> {
                try {
                    processEntityDescriptor(entityDescriptor);
                } catch (final FilterException e) {
                    LOG.error("EntityDescriptor '{}' failed certificate chain validation, removing from metadata provider", entityDescriptor.getEntityID());
                    toRemove.add(entityDescriptor);
                }
        });

        if (!toRemove.isEmpty()) {
            entitiesDescriptor.getEntityDescriptors().removeAll(toRemove);
            toRemove.clear();
        }

        entitiesDescriptor.getEntitiesDescriptors().forEach(
            internalEntitiesDescriptor -> {
                final String childName = getGroupName(internalEntitiesDescriptor);
                LOG.trace("Processing EntitiesDescriptor member: {}", childName);
                try {
                    processEntityGroup(internalEntitiesDescriptor);
                } catch (final FilterException e) {
                    LOG.error("EntitiesDescriptor '{}' failed certificate chain validation, removing from metadata provider", childName);
                    toRemove.add(internalEntitiesDescriptor);
                }
        });

        if (!toRemove.isEmpty()) {
            entitiesDescriptor.getEntitiesDescriptors().removeAll(toRemove);
        }

        if (entitiesDescriptor.getEntityDescriptors().isEmpty() && entitiesDescriptor.getEntitiesDescriptors().isEmpty()) {
            throw new FilterException("Entity Descriptors list and Entities Descriptors list are empty");
        }
    }

    private String getGroupName(final EntitiesDescriptor group) {
        String name = group.getName();
        if (name != null) {
            return name;
        }
        name = group.getID();
        if (name != null) {
            return name;
        }
        return "(unnamed)";
    }

    private void performCertificateChainValidation(final RoleDescriptor roleDescriptor) throws FilterException {
        for (final KeyDescriptor keyDescriptor : roleDescriptor.getKeyDescriptors()) {
            KeyInfo keyInfo = keyDescriptor.getKeyInfo();
            try {
                for (final X509Certificate certificate : getCertificates(keyInfo)) {
                    if (!getCertificateChainValidator().validate(certificate, getKeyStore()).isValid()) {
                        LOG.error("Certificate chain validation failed for metadata entry {}", certificate.getSubjectDN());
                        throw new FilterException("Certificate chain validation failed for metadata entry " + certificate.getSubjectDN());
                    }
                }
            } catch (CertificateException e) {
                throw new CertificateConversionException(e);
            }
        }
    }
}
