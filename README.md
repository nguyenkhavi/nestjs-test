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

## Deployment

Pull the latest code and make sure `.env` file is existed. Then follow these steps:

1. Build image with command: `docker build -t web3asy-proxy:latest .`
2. Run docker container: `docker run -p 3000:3000 web3asy-proxy:latest`

Check the current server is running on [http://localhost:3000](http://localhost:3000)

Note: you can check docker container logs with command: `docker logs -f CONTAINER_ID`
