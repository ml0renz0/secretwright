# F10 — Ciclo de vida y rotación

## Alcance

Rotar tokens de consumidor emitidos por un AppRole, publicarlos en un archivo privado y retirar la credencial anterior después de una confirmación externa. Consultar TTL, renovar tokens y leases concretos, y revocar leases explícitamente.

Son comandos puntuales para ejecución manual, cron, timers de systemd o pipelines. No existe un daemon, scheduler interno ni ejecución de scripts desde el manifiesto. El primer proveedor es AppRole y el adaptador de consumidor es un archivo de token; no se rota el contenido arbitrario de KV ni se despliegan contraseñas de bases de datos a aplicaciones.

La rotación prueba que la credencial nueva puede leer una ruta KV antes de publicarla. **Eso no demuestra que una aplicación haya recargado el archivo.** Retirar la anterior exige otro comando con `--ack-consumer`, que representa esa confirmación externa.

## Configuración y formatos

```yaml
api_version: secretwright/lifecycle/v1
name: payments-api
provider:
  kind: approle
  auth_mount: approle
  role: payments-api
consumer:
  kind: token-file
  path: /run/payments/vault-token
verify:
  kind: kv-read
  mount: lifecycle-demo
  kv_version: 2
  path: /lifecycle-demo/payments/health
policy:
  rotate_below: 5m
  minimum_new_ttl: 10m
```

El manifiesto admite YAML y JSON estrictos: campos desconocidos, duplicados, aliases, anchors, varios documentos, tags personalizados, interpolación y números ambiguos se rechazan. La entrada está limitada a 1 MiB, 64 niveles y 10 000 nodos. El esquema Draft 2020-12 publicado y embebido es `schemas/lifecycle-v1.schema.json`, con ID `urn:secretwright:lifecycle:v1`; no se cargan referencias externas.

El montaje AppRole y el rol deben existir. El archivo consumidor también debe existir, contener un token válido de ese AppRole y tener permisos `0600`; su ruta es absoluta. La instalación inicial sigue usando F06. Se exige un token service, finito, sin política root, sin usos limitados y distinto del token operador. El rol también debe emitir tokens de usos ilimitados y TTL finito. El probe es una lectura KV v2 con montaje y versión explícitos; su valor se descarta.

Los umbrales son duraciones positivas de segundos enteros, hasta 24 horas. `minimum_new_ttl` debe ser al menos `rotate_below` y dejar margen bajo el TTL que pueda conceder Vault. Por ejemplo, mínimo 10 minutos para un rol con TTL de 15 minutos. El TTL real devuelto por el servidor puede ser inferior al solicitado.

Los documentos de configuración generados usan YAML por defecto, con `--format json` opcional:

```bash
secretwright lifecycle example > rotation.yaml
secretwright lifecycle example --format json > rotation.json
secretwright lifecycle schema
secretwright lifecycle validate --file rotation.yaml

secretwright template show multi-env > architecture.yaml
secretwright template render --file architecture.yaml > blueprint.yaml
secretwright template render --file architecture.yaml --format json > blueprint.json
```

Los informes de terminal y los JSON Schema conservan JSON. Los formatos previos de backup, credenciales F06 e inventarios F09 siguen siendo compatibles. El archivo de token consumido por la aplicación conserva token crudo y salto de línea, sin envoltorio YAML. Los recibos nuevos de rotación usan YAML o JSON seleccionado al crearlos; su codificación se conserva al reabrirlos.

## Rotar y retirar

```bash
secretwright lifecycle inspect --file rotation.yaml \
  --receipt /var/lib/secretwright/payments.rotation.yaml --token-file operator-token

secretwright lifecycle rotate --file rotation.yaml \
  --receipt /var/lib/secretwright/payments.rotation.yaml --dry-run --token-file operator-token

secretwright lifecycle rotate --file rotation.yaml \
  --receipt /var/lib/secretwright/payments.rotation.yaml --token-file operator-token
```

Inspect y dry-run consultan metadatos mediante el operador. No generan SecretID, hacen login, prueban el token anterior, crean locks ni escriben artefactos. Si el TTL anterior aún supera el umbral, rotate devuelve `not_due` sin mutaciones.

Cuando corresponde rotar, la operación:

1. Comprueba configuración, archivos privados, target y lock antes de emitir credenciales.
2. Conserva una copia privada del token anterior y registra el checkpoint previo a la emisión.
3. Emite un SecretID acotado y hace login con él, sin enviar el token operador al login.
4. Guarda la candidata en un archivo privado; comprueba rol, identidad, políticas, TTL mínimo y lectura KV efectiva.
5. Reemplaza el archivo consumidor de forma atómica, conservando `0600` y UID/GID, y comprueba el contenido publicado.
6. Termina en `awaiting_consumer_ack`, conservando el token anterior válido.

Un segundo rotate pendiente de confirmación no emite otra credencial. Los checkpoints conocidos pueden continuar el siguiente paso seguro; una emisión, login, publicación o retirada incierta exige recover antes de seguir.

Después de comprobar mediante los mecanismos de la aplicación que ha recargado la nueva credencial:

```bash
secretwright lifecycle retire --file rotation.yaml \
  --receipt /var/lib/secretwright/payments.rotation.yaml \
  --ack-consumer --token-file operator-token
```

Retire vuelve a comprobar el token publicado y su probe antes de revocar únicamente el anterior y sus descendientes. No revoca la candidata si falla la retirada. Si el anterior ya ha expirado, puede confirmar su ausencia. No hay rollback automático del archivo publicado: la aplicación podría estar usando ya la credencial nueva.

## Recibos y recuperación

El recibo guarda versión, fase, generación, binding de dirección/clúster/namespace, hashes y metadatos mínimos. No contiene tokens, accessors, SecretID, RoleID, HCL ni valores del probe. Se escribe con `0600`, revisión y reemplazo atómico bajo lock cooperativo.

Los secretos necesarios para recuperación están separados en `<receipt>.d/<generation>/`, con directorios `0700` y archivos `0600`: `old.token`, `new.token` y `bundle.json`. Solo se aceptan esos nombres derivados; no se siguen symlinks ni se sobrescriben archivos privados ajenos. Los artefactos se conservan para recuperación/auditoría; su archivo o eliminación tras finalizar corresponde al operador.

```bash
secretwright lifecycle recover --file rotation.yaml \
  --receipt /var/lib/secretwright/payments.rotation.yaml --token-file operator-token
```

Recover consulta y compara estado; no repite emisión, login, revocación ni publicación. Puede reconocer artefactos que quedaron guardados, un archivo consumidor ya publicado o una retirada ya aplicada. Si el consumidor contiene un tercer valor, el binding cambió o falta evidencia, se detiene.

Una emisión/login con respuesta perdida y sin candidata recuperable permanece bloqueada. `recover --abandon` permite reconocer explícitamente ese resultado desconocido solo antes de publicar, con el consumidor anterior intacto y sin una candidata conocida todavía viva. No demuestra que no se emitieran credenciales: las desconocidas permanecen limitadas por sus TTL. Una candidata conocida viva debe revocarse explícitamente con F06 antes de abandonarla.

No se roban locks automáticamente. Si queda uno tras un crash, el operador debe comprobar que no exista una operación activa antes de retirarlo. La protección de archivos es cooperativa y presupone un sistema de archivos local confiado.

## TTL de tokens y leases

```bash
secretwright lifecycle token inspect --file app-token --token-file operator-token
secretwright lifecycle token renew --file app-token --increment 15m \
  --if-ttl-below 5m --token-file operator-token

secretwright lifecycle lease inspect --file lease.yaml --token-file operator-token
secretwright lifecycle lease renew --file lease.yaml --increment 15m \
  --if-ttl-below 5m --token-file operator-token
secretwright lifecycle lease revoke --file lease.yaml --force --token-file operator-token
```

El archivo de lease es privado `0600` y contiene únicamente `lease_id`, en YAML o JSON. Tokens e IDs entran por archivos y cuerpos HTTP, nunca como valores argv, URL ni salida de informes. La inspección del token objetivo se autentica con un operador distinto para evitar consumir usos del consumidor.

Renew consulta primero: si no corresponde por umbral, devuelve noop; si no es renovable, se rechaza antes de mutar. El incremento debe ser positivo y no superar 24 horas; el informe muestra el TTL real concedido. Revoke afecta únicamente al lease exacto y exige `--force` salvo dry-run; no admite prefijos ni revocación forzada de Vault. La ausencia de un lease/token se distingue de una denegación de permisos del operador.

## Ejecución y resultados

Los comandos online aceptan la conexión y timeout existentes; este último cubre la operación completa. La shell conserva su conexión de inicio, excluye lifecycle del historial y no completa archivos ni valores sensibles. Schema, example, validate y su ayuda son offline.

Los informes son metadatos JSON con operación, fase, estado y TTL. No muestran contenidos de archivos, identificadores de lease, secretos ni diagnósticos arbitrarios de Vault. Los errores y las escrituras truncadas de stdout se detectan.

Códigos: `0` éxito/noop; `1` entrada/configuración/archivo; `2` autenticación o permisos; `3` recurso ausente; `4` conflicto/binding/lock; `5` resultado parcial o incierto; `130` cancelación sin cambios. Un resultado incierto detiene la operación sin retry automático.

## Aceptación

Contrato y pruebas se publican antes de implementar. Se exige regresión F00–F09 y:

- YAML por defecto y JSON explícito, sin cambiar tipos al revalidar blueprints.
- Rotación con Vault real: candidata válida y publicada, anterior aún usable hasta ack, anterior revocada después y nueva todavía usable.
- Probe fallido, targets peligrosos, usos limitados, bindings/proofs alterados, cancelación, locks y fallos de publicación/checkpoints.
- Recovery sin replay y receipts sin credenciales, junto a artefactos privados y preservación de propiedad del archivo consumidor.
- Noops por TTL y dry-run sin mutaciones/artefactos, renovación con TTL real y rechazo de no renovables.
- Token renovable y lease de PostgreSQL real renovado/revocado; CI exige esa fixture. El fallback local sin Docker señala explícitamente que omite la prueba de base de datos.
- Smoke del binario y shell, privacidad de capturas y compatibilidad de formatos anteriores.
