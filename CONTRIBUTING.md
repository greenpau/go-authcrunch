# Contributing Guidelines

## Contributor License Agreements

I'd love to accept your pull request! Before I can take them, we have to jump a
couple of legal hurdles.

Please see [`assets/cla/CLA.md`](assets/cla/CLA.md).

Please follow these steps to add CLA consent:

1. Add your info to `assets/cla/consent.yaml`
2. Agree to CLA via comment in PR. See [here](https://github.com/contributor-assistant/github-action#demo-for-step-2-and-3)
  how to do it.

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
