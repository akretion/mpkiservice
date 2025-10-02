# Mpki Service


# Use hatch

Install the env with all lib

```
hatch env create
```


Execute the test

```
cd tests
export MPKISERVICE_CONFIG_PATH=config.yaml
# Generate the default test config (run only once)
mpkiservice-cli add bob incroyableeponge supersecret FR Rhone-Alpes Akretion IT Akretion akretion@example.org
# Run the test
hatch run test:pytest
```

Start Env (in case that you when to have the python env activated to run cmd)

```
hatch shell
```


# Configuration

You need to configure the file "config.yaml"

# Adding a new ca

you can run the following cmd to add a new authority

```
mpkiservice-cli add bob incroyableeponge supersecret FR Rhone-Alpes Akretion IT Akretion akretion@example.org
```
