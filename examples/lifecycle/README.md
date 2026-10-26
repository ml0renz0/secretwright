# Rotación de un token de aplicación

Utiliza un laboratorio y un token de operador con permisos adecuados, conservado fuera del repositorio. El montaje AppRole `approle` debe existir. `provision.yaml` declara el KV v2, la política de lectura del probe y el AppRole; no introduce valores secretos ni credenciales.

```bash
secretwright blueprint plan --file examples/lifecycle/provision.yaml --token-file operator-token
secretwright blueprint apply --file examples/lifecycle/provision.yaml --token-file operator-token
```

Prepara la ruta del probe mediante un archivo JSON local, por ejemplo `probe.json` con `{"ready":true}`, y escribe el valor con el operador:

```bash
secretwright put --file probe.json --mount lifecycle-demo --kv-version 2 \
  --token-file operator-token /lifecycle-demo/payments/health
```

La primera credencial se instala explícitamente con F06. Selecciona un directorio privado apropiado para el usuario consumidor; el archivo de salida no debe existir:

```bash
secretwright approle credentials --auth-mount approle --out bootstrap.bundle.json \
  --token-file operator-token payments-api
secretwright approle login --auth-mount approle --file bootstrap.bundle.json \
  --out /run/payments/vault-token
```

Copia `rotation.yaml`, ajusta la ruta absoluta del consumidor y valida. El ejemplo rota por debajo de cinco minutos, de modo que una credencial recién emitida con TTL de quince minutos normalmente devuelve `not_due`:

```bash
secretwright lifecycle validate --file rotation.yaml
secretwright lifecycle rotate --file rotation.yaml \
  --receipt /var/lib/secretwright/payments.rotation.yaml --dry-run --token-file operator-token
secretwright lifecycle rotate --file rotation.yaml \
  --receipt /var/lib/secretwright/payments.rotation.yaml --token-file operator-token
```

La salida informa si todavía no corresponde rotar o si la candidata ya está publicada y espera confirmación. Comprueba mediante los mecanismos propios de tu aplicación que haya recargado el archivo; después:

```bash
secretwright lifecycle retire --file rotation.yaml \
  --receipt /var/lib/secretwright/payments.rotation.yaml --ack-consumer --token-file operator-token
```

Un timer externo puede invocar rotate periódicamente. No programes una confirmación ciega: retire debe suceder después de la señal de readiness/recarga de tu consumidor. No hay daemon ni hooks ejecutables dentro del manifiesto.

Conserva recibos, directorios de generaciones y credenciales con sus permisos privados y fuera de Git. Tras resultados inciertos, consulta `lifecycle recover`; no fabriques hashes ni borres checkpoints para forzar un reintento. El [contrato F10](../../docs/features/F10-lifecycle-rotation.md) detalla fases, formatos y límites.
