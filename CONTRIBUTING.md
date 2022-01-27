# Contributing Guidelines

## Contributor License Agreements

I'd love to accept your pull request! Before I can take them, we have to jump a
couple of legal hurdles.

***NOTE***: Only original source code from you and other people that have
signed the CLA can be accepted into the main repository.

Please fill out either the individual or corporate Contributor License Agreement (CLA).
* If you are an individual writing original source code and you're sure you own the
  intellectual property, then you'll need to sign an [individual CLA](/assets/cla/individual_cla.md).
* If you work for a company that wants to allow you to contribute your work, then
  you'll need to sign a [corporate CLA](/assets/cla/corporate_cla.md).

Follow either of the two links above to access the appropriate CLA. Next,
accept the CLA in the following way.

For Individual CLA:
1. Review the Individual CLA provided in `assets/cla/individual_cla.md`
2. Consent to the CLA by adding your name and email address to
  the `assets/cla/consent.yaml` file.

For Corporate CLA:
1. Review the Corporate CLA provided in `assets/cla/corporate_cla.md`
2. Consent to the CLA by adding your name and email address, and business
  name to the `assets/cla/consent.yaml` file.

## Pull Request Checklist

Before sending your pull requests, make sure you followed this list.

1. Open an issue to discuss your PR
2. Ensure you read appropriate Contributor License Agreement (CLA)
3. Run unit tests

## Development Environment

The contribution to this project requires setting up a development
environment. The following steps allow developers to test their
code changes.

```bash
git clone git@github.com:greenpau/go-authcrunch.git
cd go-authcrunch/
make dep
make ctest
```
