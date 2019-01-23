Verify SAML Libraries 📚
========================

[![Build Status](https://deployer.tools.signin.service.gov.uk/api/v1/teams/main/pipelines/continuously-deploy/jobs/build-verify-saml-libs/badge)](https://deployer.tools.signin.service.gov.uk/teams/main/pipelines/continuously-deploy/jobs/build-verify-saml-libs/builds/latest)

The individual SAML libraries used by Verify have been combined in this repository to make managing dependencies easier.

Affected libraries:

* saml-extensions
* saml-security
* saml-utils
* saml-serializers
* saml-metadata-bindings
* saml-metadata-bindings-test

### Building the project

`./gradlew clean build`

## Licence

[MIT Licence](LICENCE)

This code is provided for informational purposes only and is not yet intended for use outside GOV.UK Verify
