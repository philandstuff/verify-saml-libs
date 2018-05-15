package uk.gov.ida.saml.core.transformers;

import org.joda.time.LocalDate;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.domain.AddressFactory;
import uk.gov.ida.saml.core.domain.SimpleMdsValue;
import uk.gov.ida.saml.core.extensions.eidas.CurrentFamilyName;
import uk.gov.ida.saml.core.extensions.eidas.CurrentGivenName;
import uk.gov.ida.saml.core.extensions.eidas.DateOfBirth;
import uk.gov.ida.saml.core.extensions.eidas.PersonIdentifier;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;

public class EidasMatchingDatasetUnmarshaller extends MatchingDatasetUnmarshaller{

    private static final Logger LOG = LoggerFactory.getLogger(EidasMatchingDatasetUnmarshaller.class);

    public EidasMatchingDatasetUnmarshaller() {
    }

    @Override
    protected void transformAttribute(Attribute attribute, MatchingDatasetBuilder datasetBuilder) {
        switch (attribute.getName()) {
            case IdaConstants.Eidas_Attributes.FirstName.NAME:
                datasetBuilder.firstname(transformEidasGivenNameAttribute(attribute));
                break;

            case IdaConstants.Eidas_Attributes.FamilyName.NAME:
                datasetBuilder.addSurnames(transformEidasFamilyNameAttribute(attribute));
                break;

            case IdaConstants.Eidas_Attributes.DateOfBirth.NAME:
                datasetBuilder.dateOfBirth(transformEidasDateOfBirthAttribute(attribute));
                break;
                
            case IdaConstants.Eidas_Attributes.PersonIdentifier.NAME:
                // This is set on the datasetBuilder in the abstract base class - see getPersonalIdentifier
                break;

            default:
                String errorMessage = format("Attribute {0} is not a supported Eidas Matching Dataset attribute.", attribute.getName());
                LOG.warn(errorMessage);
                throw new IllegalArgumentException(errorMessage);
        }
    }

    @Override
    protected String getPersonalIdentifier(Assertion assertion) {
        return assertion.getAttributeStatements().get(0).getAttributes()
                .stream()
                .filter(a -> a.getName().equals(IdaConstants.Eidas_Attributes.PersonIdentifier.NAME))
                .findFirst()
                .map(a -> ((PersonIdentifier)a.getAttributeValues().get(0)).getPersonIdentifier())
                .orElseThrow(() -> {
                    String errorMessage = "No PersonalIdentifier found in Matching Dataset Assertion";
                    LOG.warn(errorMessage);
                    return new IllegalArgumentException(errorMessage);
                });
    }


    private List<SimpleMdsValue<String>> transformEidasGivenNameAttribute(Attribute attribute) {
        List<SimpleMdsValue<String>> personNames = new ArrayList<>();

        for (XMLObject xmlObject : attribute.getAttributeValues()) {
            CurrentGivenName personName = (CurrentGivenName) xmlObject;
            // There are no from/to dates for eIDAS attributes
            personNames.add(new SimpleMdsValue<>(personName.getFirstName(), null, null, true));
        }
        return personNames;
    }

    private List<SimpleMdsValue<String>> transformEidasFamilyNameAttribute(Attribute attribute) {
        List<SimpleMdsValue<String>> personNames = new ArrayList<>();

        for (XMLObject xmlObject : attribute.getAttributeValues()) {
            CurrentFamilyName personName = (CurrentFamilyName) xmlObject;
            // There are no from/to dates for eIDAS attributes
            personNames.add(new SimpleMdsValue<>(personName.getFamilyName(), null, null, true));
        }
        return personNames;
    }

    private List<SimpleMdsValue<LocalDate>> transformEidasDateOfBirthAttribute(Attribute attribute) {
        List<SimpleMdsValue<LocalDate>> datesOfBirth = new ArrayList<>();

        for (XMLObject xmlObject : attribute.getAttributeValues()) {
            DateOfBirth dateOfBirth = (DateOfBirth) xmlObject;
            // There are no from/to dates for eIDAS attributes
            datesOfBirth.add(new SimpleMdsValue<>(dateOfBirth.getDateOfBirth(), null, null, true));
        }
        return datesOfBirth;
    }
}
