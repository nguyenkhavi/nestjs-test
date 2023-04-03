# Web3asy proxy documentation

## Getting Started

### Installing

In order to run the Proxy Server, you will need to make sure that the following
dependencies are installed on your system:
  - node
  - yarn

### Folder structure

Here's a folder structure for a Pandoc document:

```
web3asy-proxy/   # Root directory.
|- dist/         # Folder used to store builded (output) files.
|- src/          # Modules
|- package.json  # Metadata content (title, author...).
|- README.md     # Markdown used for building our documents.
|- .env.example  # The example of .env file.
```

### Step to run
- Create `.env` which re-define all variables exists in `.env.example`
- Run `yarn prisma:generate`
- Run `yarn start:dev`

```
## Deployment
