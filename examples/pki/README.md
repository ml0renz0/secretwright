# Certificado de aplicación y CSR local

Usa un laboratorio con un montaje PKI y un rol `web` existentes que permitan `web.example.test`, la IP `127.0.0.1`, el uso server-auth y el TTL elegido. Para issue, el rol debe emitir claves EC de 256 bits. La configuración de la CA y del rol pertenece al administrador de Vault.

Selecciona las raíces confiables de tu organización en `roots.pem`; una CA descargada de Vault no se considera confiable automáticamente. Conserva el token operador y las claves fuera de Git.

```bash
secretwright pki validate --file examples/pki/request.yaml

# La clave se genera y conserva localmente.
secretwright pki csr create --file examples/pki/request.yaml \
  --out web.csr --key-out web.key
secretwright pki csr inspect --file web.csr

# Vault recibe la CSR, no la clave privada.
secretwright pki sign --mount pki --role web --file examples/pki/request.yaml \
  --csr web.csr --ca-file roots.pem --out web.pem --token-file operator-token

secretwright pki cert verify --file web.pem --ca-file roots.pem \
  --hostname web.example.test --usage server-auth
secretwright pki cert match --file web.pem --key web.key
```

Issue es la alternativa en la que Vault genera la clave y Secretwright guarda una identidad PEM privada completa:

```bash
secretwright pki issue --mount pki --role web --file examples/pki/request.yaml \
  --ca-file roots.pem --out identity.pem --token-file operator-token
secretwright pki cert inspect --file identity.pem
secretwright pki key inspect --file identity.pem
```

Cuando corresponda retirar un certificado:

```bash
secretwright pki revoke --mount pki --file web.pem --force --token-file operator-token
```

La verificación local comprueba cadena, tiempo, nombres y usos; no consulta CRL ni OCSP. La aplicación que consume el certificado decide cómo comprobar revocación. Consulta el [contrato F11](../../docs/features/F11-x509-pki.md) para formatos, recuperación de fallos y límites.
