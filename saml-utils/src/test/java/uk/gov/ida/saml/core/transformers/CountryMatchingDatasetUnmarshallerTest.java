package uk.gov.ida.saml.core.transformers;

import org.joda.time.DateTime;
import org.joda.time.LocalDate;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import uk.gov.ida.saml.core.domain.AddressFactory;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.domain.SimpleMdsValue;
import uk.gov.ida.saml.core.extensions.Address;
import uk.gov.ida.saml.core.extensions.Gender;
import uk.gov.ida.saml.core.extensions.PersonName;
import uk.gov.ida.saml.core.extensions.eidas.PersonIdentifier;
import uk.gov.ida.saml.core.extensions.eidas.impl.PersonIdentifierBuilder;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.saml.core.test.builders.AddressAttributeBuilder_1_1.anAddressAttribute;
import static uk.gov.ida.saml.core.test.builders.AddressAttributeValueBuilder_1_1.anAddressAttributeValue;
import static uk.gov.ida.saml.core.test.builders.AssertionBuilder.anAssertion;
import static uk.gov.ida.saml.core.test.builders.AssertionBuilder.anEidasMatchingDatasetAssertion;
import static uk.gov.ida.saml.core.test.builders.AttributeStatementBuilder.anAttributeStatement;
import static uk.gov.ida.saml.core.test.builders.DateAttributeBuilder_1_1.aDate_1_1;
import static uk.gov.ida.saml.core.test.builders.DateAttributeValueBuilder.aDateValue;
import static uk.gov.ida.saml.core.test.builders.GenderAttributeBuilder_1_1.aGender_1_1;
import static uk.gov.ida.saml.core.test.builders.PersonIdentifierAttributeBuilder.aPersonIdentifier;
import static uk.gov.ida.saml.core.test.builders.PersonNameAttributeBuilder_1_1.aPersonName_1_1;
import static uk.gov.ida.saml.core.test.builders.PersonNameAttributeValueBuilder.aPersonNameValue;

@RunWith(OpenSAMLMockitoRunner.class)
public class CountryMatchingDatasetUnmarshallerTest {

    private CountryMatchingDatasetUnmarshaller unmarshaller;

    @Before
    public void setUp() {
        this.unmarshaller = new CountryMatchingDatasetUnmarshaller(new AddressFactory());
    }

    @Test
    public void transform_shouldTransformAnAssertionIntoAMatchingDataset() {
        Attribute firstname = aPersonName_1_1().addValue(aPersonNameValue().withValue("Bob").withFrom(DateTime.parse("2000-03-5")).withTo(DateTime.parse("2001-02-6")).withVerified(true).build()).buildAsEidasFirstname();
        Attribute surname = aPersonName_1_1().addValue(aPersonNameValue().withValue("Bobbins").withFrom(DateTime.parse("2000-03-5")).withTo(DateTime.parse("2001-02-6")).withVerified(true).build()).buildAsEidasFamilyName();
        Attribute gender = aGender_1_1().withValue("Male").withFrom(DateTime.parse("2000-03-5")).withTo(DateTime.parse("2001-02-6")).withVerified(true).buildEidasGender();
        Attribute dateOfBirth = aDate_1_1().addValue(aDateValue().withValue("1986-12-05").withFrom(DateTime.parse("2001-09-08")).withTo(DateTime.parse("2002-03-05")).withVerified(false).build()).buildAsEidasDateOfBirth();
        Address address = anAddressAttributeValue().addLines(asList("address-line-1")).withFrom(DateTime.parse("2012-08-08")).withTo(DateTime.parse("2012-09-09")).build();
        Attribute currentAddress = anAddressAttribute().addAddress(address).buildEidasCurrentAddress();

        PersonIdentifier personIdentifier = new PersonIdentifierBuilder().buildObject();
        personIdentifier.setPersonIdentifier("PID12345");
        Attribute personalIdentifier = aPersonIdentifier().withValue(personIdentifier).build();
        Assertion originalAssertion = anEidasMatchingDatasetAssertion(firstname, surname, gender, dateOfBirth, currentAddress, personalIdentifier).buildUnencrypted();

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(originalAssertion);

        final PersonName firstNameAttributeValue = (PersonName) firstname.getAttributeValues().get(0);
        final PersonName surnameAttributeValue = (PersonName) surname.getAttributeValues().get(0);
        final PersonIdentifier personalIdentifierAttributeValue = (PersonIdentifier) personalIdentifier.getAttributeValues().get(0);

        final Gender genderAttributeValue = (Gender) gender.getAttributeValues().get(0);
        final uk.gov.ida.saml.core.extensions.Date dateOfBirthAttributeValue = (uk.gov.ida.saml.core.extensions.Date) dateOfBirth.getAttributeValues().get(0);
        final Address currentAddressAttributeValue = (Address) currentAddress.getAttributeValues().get(0);
        assertThat(matchingDataset.getFirstNames().get(0).getValue()).isEqualTo(firstNameAttributeValue.getValue());
        assertThat(matchingDataset.getFirstNames().get(0).getFrom()).isEqualTo(firstNameAttributeValue.getFrom());
        assertThat(matchingDataset.getFirstNames().get(0).getTo()).isEqualTo(firstNameAttributeValue.getTo());
        
        assertThat(matchingDataset.getSurnames().get(0).getValue()).isEqualTo(surnameAttributeValue.getValue());
        assertThat(matchingDataset.getSurnames().get(0).getFrom()).isEqualTo(surnameAttributeValue.getFrom());
        assertThat(matchingDataset.getSurnames().get(0).getTo()).isEqualTo(surnameAttributeValue.getTo());

        SimpleMdsValue<String> unmarshalledPersonalIdentifier = matchingDataset.getPersonalId().get(0);
        assertThat(unmarshalledPersonalIdentifier.getValue()).isEqualTo(personalIdentifierAttributeValue.getPersonIdentifier());
        assertThat(unmarshalledPersonalIdentifier.getTo()).isNull();
        assertThat(unmarshalledPersonalIdentifier.getFrom()).isNull();

        assertThat(matchingDataset.getGender().get().getValue().getValue()).isEqualTo(genderAttributeValue.getValue());
        assertThat(matchingDataset.getGender().get().getFrom()).isEqualTo(genderAttributeValue.getFrom());
        assertThat(matchingDataset.getGender().get().getTo()).isEqualTo(genderAttributeValue.getTo());

        assertThat(matchingDataset.getDateOfBirths().get(0).getValue()).isEqualTo(LocalDate.parse(dateOfBirthAttributeValue.getValue()));
        assertThat(matchingDataset.getDateOfBirths().get(0).getFrom()).isEqualTo(dateOfBirthAttributeValue.getFrom());
        assertThat(matchingDataset.getDateOfBirths().get(0).getTo()).isEqualTo(dateOfBirthAttributeValue.getTo());

        assertThat(matchingDataset.getAddresses().size()).isEqualTo(1);

        uk.gov.ida.saml.core.domain.Address transformedCurrentAddress = matchingDataset.getAddresses().get(0);
        assertThat(transformedCurrentAddress.getLines().get(0)).isEqualTo(currentAddressAttributeValue.getLines().get(0).getValue());
        assertThat(transformedCurrentAddress.getPostCode().get()).isEqualTo(currentAddressAttributeValue.getPostCode().getValue());
        assertThat(transformedCurrentAddress.getInternationalPostCode().get()).isEqualTo(currentAddressAttributeValue.getInternationalPostCode().getValue());
        assertThat(transformedCurrentAddress.getUPRN().get()).isEqualTo(currentAddressAttributeValue.getUPRN().getValue());
        assertThat(transformedCurrentAddress.getFrom()).isEqualTo(currentAddressAttributeValue.getFrom());
        assertThat(transformedCurrentAddress.getTo().get()).isEqualTo(currentAddressAttributeValue.getTo());
    }

    @Test
    public void transform_shoulHandleWhenMatchingDatasetIsPresentAndToDateIsMissingFromCurrentAddress() {
        Attribute currentAddress = anAddressAttribute().addAddress(anAddressAttributeValue().withTo(null).build()).buildEidasCurrentAddress();
        Assertion assertion = anEidasMatchingDatasetAssertion(
                aPersonName_1_1().buildAsEidasFirstname(),
                aPersonName_1_1().buildAsEidasFamilyName(),
                aGender_1_1().buildEidasGender(),
                aDate_1_1().buildAsEidasDateOfBirth(),
                currentAddress,
                aPersonIdentifier().build())
                .buildUnencrypted();

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(assertion);

        assertThat(matchingDataset).isNotNull();
    }

    @Test
    public void transform_shoulHandleWhenMatchingDatasetIsPresentAndToDateIsMissingFromFirstName() {
        Attribute firstName = aPersonName_1_1().addValue(aPersonNameValue().withTo(null).build()).buildAsEidasFirstname();
        Assertion assertion = anEidasMatchingDatasetAssertion(
                firstName,
                aPersonName_1_1().buildAsEidasFamilyName(),
                aGender_1_1().buildEidasGender(),
                aDate_1_1().buildAsEidasDateOfBirth(),
                anAddressAttribute().addAddress(anAddressAttributeValue().build()).buildEidasCurrentAddress(),
                aPersonIdentifier().build())
                .buildUnencrypted();

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(assertion);

        assertThat(matchingDataset).isNotNull();
    }

    @Test
    public void transform_shoulHandleWhenMatchingDatasetIsPresentAndToDateIsPresentInFirstName() {
        Attribute firstName = aPersonName_1_1().addValue(aPersonNameValue().withTo(DateTime.parse("1066-01-05")).build()).buildAsEidasFirstname();
        Assertion assertion = anEidasMatchingDatasetAssertion(
                firstName,
                aPersonName_1_1().buildAsEidasFamilyName(),
                aGender_1_1().buildEidasGender(),
                aDate_1_1().buildAsEidasDateOfBirth(),
                anAddressAttribute().addAddress(anAddressAttributeValue().build()).buildEidasCurrentAddress(),
                aPersonIdentifier().build())
                .buildUnencrypted();

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(assertion);

        assertThat(matchingDataset).isNotNull();
    }

    @Test
    public void transform_shouldMapMultipleFirstNames() {
        Attribute firstName = aPersonName_1_1()
                .addValue(aPersonNameValue().withValue("name1").build())
                .addValue(aPersonNameValue().withValue("name2").build())
                .buildAsEidasFirstname();

        AttributeStatement attributeStatementBuilder = anAttributeStatement().addAttribute(firstName).build();
        Assertion matchingDatasetAssertion = anAssertion()
                .addAttributeStatement(attributeStatementBuilder)
                .buildUnencrypted();

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(matchingDatasetAssertion);

        assertThat(matchingDataset).isNotNull();
        assertThat(matchingDataset.getFirstNames().size()).isEqualTo(2);
    }
    @Test
    public void transform_shouldMapMultipleSurnames() {
        Attribute surName = aPersonName_1_1()
                .addValue(aPersonNameValue().withValue("name1").build())
                .addValue(aPersonNameValue().withValue("name2").build())
                .buildAsEidasFamilyName();

        AttributeStatement attributeStatementBuilder = anAttributeStatement().addAttribute(surName).build();
        Assertion matchingDatasetAssertion = anAssertion()
                .addAttributeStatement(attributeStatementBuilder)
                .buildUnencrypted();

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(matchingDatasetAssertion);

        assertThat(matchingDataset).isNotNull();
        assertThat(matchingDataset.getSurnames().size()).isEqualTo(2);
    }

    @Test
    public void transform_shouldMapMultipleBirthdates() {
        Attribute attribute = aDate_1_1().addValue(aDateValue().withValue("2012-12-12").build()).addValue(aDateValue().withValue("2011-12-12").build()).buildAsEidasDateOfBirth();

        AttributeStatement attributeStatementBuilder = anAttributeStatement().addAttribute(attribute).build();
        Assertion matchingDatasetAssertion = anAssertion()
                .addAttributeStatement(attributeStatementBuilder)
                .buildUnencrypted();

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(matchingDatasetAssertion);

        assertThat(matchingDataset).isNotNull();
        assertThat(matchingDataset.getDateOfBirths().size()).isEqualTo(2);
    }

    @Test
    public void transform_shouldMapMultipleCurrentAddresses() {
        Attribute attribute = anAddressAttribute().addAddress(anAddressAttributeValue().build()).addAddress(anAddressAttributeValue().build()).buildEidasCurrentAddress();

        AttributeStatement attributeStatementBuilder = anAttributeStatement().addAttribute(attribute).build();
        Assertion matchingDatasetAssertion = anAssertion()
                .addAttributeStatement(attributeStatementBuilder)
                .buildUnencrypted();

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(matchingDatasetAssertion);

        assertThat(matchingDataset).isNotNull();
        assertThat(matchingDataset.getAddresses().size()).isEqualTo(2);
    }
}
