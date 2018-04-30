package uk.gov.ida.saml.core.transformers;

import org.opensaml.saml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.domain.Address;
import uk.gov.ida.saml.core.domain.AddressFactory;
import uk.gov.ida.saml.core.domain.Gender;
import uk.gov.ida.saml.core.domain.SimpleMdsValue;

import java.util.List;

import static java.text.MessageFormat.format;

public class CountryMatchingDatasetUnmarshaller extends MatchingDatasetUnmarshaller{

    private static final Logger LOG = LoggerFactory.getLogger(CountryMatchingDatasetUnmarshaller.class);
    private final AddressFactory addressFactory;

    public CountryMatchingDatasetUnmarshaller(AddressFactory addressFactory) {
        this.addressFactory = addressFactory;
    }

    @Override
    protected void transformAttribute(Attribute attribute, MatchingDatasetBuilder datasetBuilder) {
        switch (attribute.getName()) {
            case IdaConstants.Eidas_Attributes.FirstName.NAME:
                datasetBuilder.firstname(transformPersonNameAttribute(attribute));
                break;

            case IdaConstants.Eidas_Attributes.FamilyName.NAME:
                datasetBuilder.addSurnames(transformPersonNameAttribute(attribute));
                break;

            case IdaConstants.Eidas_Attributes.Gender.NAME:
                uk.gov.ida.saml.core.extensions.Gender gender = (uk.gov.ida.saml.core.extensions.Gender) attribute.getAttributeValues().get(0);
                datasetBuilder.gender(new SimpleMdsValue<>(Gender.fromString(gender.getValue()), gender.getFrom(), gender.getTo(), gender.getVerified()));
                break;

            case IdaConstants.Eidas_Attributes.DateOfBirth.NAME:
                datasetBuilder.dateOfBirth(getBirthdates(attribute));
                break;

            case IdaConstants.Eidas_Attributes.CurrentAddress.NAME:
                List<Address> transformedCurrentAddresses = addressFactory.create(attribute);
                datasetBuilder.addCurrentAddresses(transformedCurrentAddresses);
                break;
                
            case IdaConstants.Eidas_Attributes.PersonIdentifier.NAME:
                datasetBuilder.personalId(getPersonalIds(attribute));
                break;
            default:
                String errorMessage = format("Attribute {0} is not a supported Eidas Matching Dataset attribute.", attribute.getName());
                LOG.warn(errorMessage);
                throw new IllegalArgumentException(errorMessage);
        }
    }
}
