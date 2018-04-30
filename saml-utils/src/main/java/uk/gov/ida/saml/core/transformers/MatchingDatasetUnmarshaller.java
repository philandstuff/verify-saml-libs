package uk.gov.ida.saml.core.transformers;

import org.joda.time.LocalDate;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.domain.SimpleMdsValue;
import uk.gov.ida.saml.core.extensions.PersonName;
import uk.gov.ida.saml.core.extensions.StringBasedMdsAttributeValue;
import uk.gov.ida.saml.core.extensions.eidas.PersonIdentifier;

import java.util.ArrayList;
import java.util.List;

/**
 * This class has been abstracted into a hierarchy. If you were using it as a concrete class for uk idp matching sets
 * It is suggested that you use {@link VerifyMatchingDatasetUnmarshaller} instead.
 */
public abstract class MatchingDatasetUnmarshaller {

    public MatchingDataset fromAssertion(Assertion assertion) {
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements.isEmpty()) {
            // this returns null, and the consumer would wrap it with fromNullable.  Not awesome but it works.
            return null;
        }

        List<Attribute> attributes = attributeStatements.get(0).getAttributes();
        MatchingDatasetBuilder datasetBuilder = new MatchingDatasetBuilder();
        for (Attribute attribute : attributes) {
            transformAttribute(attribute, datasetBuilder);
        }

        return datasetBuilder.build();
    }

    protected abstract void transformAttribute(Attribute attribute, MatchingDatasetBuilder datasetBuilder);

    final List<SimpleMdsValue<LocalDate>> getBirthdates(Attribute attribute) {
        List<SimpleMdsValue<LocalDate>> birthDates = new ArrayList<>();

        for (XMLObject xmlObject : attribute.getAttributeValues()) {
            StringBasedMdsAttributeValue stringBasedMdsAttributeValue = (StringBasedMdsAttributeValue) xmlObject;
            String dateOfBirthString = stringBasedMdsAttributeValue.getValue();
            birthDates.add(new SimpleMdsValue<>(
                    LocalDate.parse(dateOfBirthString),
                    stringBasedMdsAttributeValue.getFrom(),
                    stringBasedMdsAttributeValue.getTo(),
                    stringBasedMdsAttributeValue.getVerified()));
        }

        return birthDates;
    }

    final List<SimpleMdsValue<String>> getPersonalIds(Attribute attribute) {
        List<SimpleMdsValue<String>> pids = new ArrayList<>();

        for (XMLObject xmlObject : attribute.getAttributeValues()) {
            PersonIdentifier personName = (PersonIdentifier) xmlObject;
            pids.add(new SimpleMdsValue<>(personName.getPersonIdentifier(), null, null, true));
        }

        return pids;
    }

    final List<SimpleMdsValue<String>> transformPersonNameAttribute(Attribute attribute) {
        List<SimpleMdsValue<String>> personNames = new ArrayList<>();

        for (XMLObject xmlObject : attribute.getAttributeValues()) {
            PersonName personName = (PersonName) xmlObject;
            personNames.add(new SimpleMdsValue<>(personName.getValue(), personName.getFrom(), personName.getTo(), personName.getVerified()));
        }

        return personNames;
    }
}
