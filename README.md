# drbac

## setup

This project uses poetry to run scripts

## run script

below example shows how to run drbac/entity/client.py

```bash
$ poetry run entity-client
```

## entity <-> central

### 1. Initialize crypted channel

send entity -> central

{
    "type": "CRYPTO_CHANNEL_REQ1",
    "data": {
        "public_key": "xxxxx"
    }
}

send central -> entity

{
    "type": "CRYPTO_CHANNEL_RES1_OK",
    "data": {
        "public_key": "xxxxx"
    }
}

or

{
    "type": "CRYPTO_CHANNEL_RES1_FAILED",
    "data": {
        "reason": "xxxxx"
    }
}

### 2. (entity -> server) authenticate entity

send entity -> central

{
    "type": "AUTH_IDENTIFICATE_REQ1",
    "data": {
        "name": "Entity(.User)",
        "public_key_blob": "xxxxxxxxxxx"
    }
}

send central -> entity

{
    "type": "AUTH_IDENTIFICATE_RES1_OK",
    "data": {}
}

or

{
    "type": "AUTH_IDENTIFICATE_RES1_FAILED",
    "data": {
        "reason": "xxxxxxx"
    }
}

send entity -> central

{
    "type": "AUTH_IDENTIFICATE_REQ2",
    "data": {
        "name": "Entity(.User)",
        "signature": "xxxxxxxxxxxx"
    }
}

send central -> entity

{
    "type": "AUTH_IDENTIFICATE_RES2_OK",
    "data": {
        "common_key": "xxxxxxxxxxxx"
    }
}

or

{
    "type": "AUTH_IDENTIFICATE_RES2_FAILED",
    "data": {
        "reason": "xxxxxxx"
    }
}