# Auth Portal UI Templates

## Formatting

First, install `prettier` and a plugin for processing go templates.

```
npm install -g prettier prettier-plugin-go-template
```

Next, use it to format the templates.

```
cd assets/portal/templates
prettier --write --parser go-template authcrunch/login.template
```
