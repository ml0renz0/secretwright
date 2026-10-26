# Inventario y custodia de un keytab

Utiliza un keytab aprovisionado por el administrador de Kerberos y conservado fuera de Git, con permisos `0600`. Ajusta `policy.yaml` al realm, componentes, KVNO y cifrados esperados. Los comandos no crean claves ni comprueban autenticación contra el KDC.

```bash
secretwright keytab inspect --file service.keytab
secretwright keytab validate --file service.keytab --policy examples/keytab/policy.yaml
```

Con un montaje KV v2 `secret` ya existente y un token con acceso a la ruta elegida:

```bash
secretwright keytab import --file service.keytab --policy examples/keytab/policy.yaml \
  --mount secret --path /secret/kerberos/web --token-file operator-token

secretwright keytab export --mount secret --path /secret/kerberos/web \
  --out recovered.keytab --policy examples/keytab/policy.yaml --token-file operator-token
```

Las rutas de salida deben ser nuevas. Import usa CAS `0`; para actualizar una ruta existente selecciona explícitamente su revisión actual mediante `--cas N`. Export permite `--version N` para una revisión histórica exacta y no utiliza otra si falta la solicitada.

Vault conserva el binario completo codificado en base64, incluidos huecos y padding. Esa codificación no añade cifrado. Los informes muestran solo metadatos y siempre indican `authentication_checked: false`; los timestamps no acreditan caducidad ni vigencia de una cuenta.

El [contrato F12](../../docs/features/F12-kerberos-keytab.md) detalla la política, los formatos y los resultados inciertos.
