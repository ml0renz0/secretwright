# Secretwright

Shell interactiva y gestión declarativa del ciclo de vida de secretos para HashiCorp Vault.

Secretwright nace como una reescritura en Go de [VCLI](https://github.com/ml0renz0/vcli). El objetivo es conservar su experiencia de shell y distribuir un único binario, incorporando progresivamente gestión de accesos, blueprints componibles, reconciliación y rotación de credenciales.

## Estado del proyecto

**F00–F13 están integradas**: conexión, KV v1/v2, shell, backup/restore, accesos, blueprints, templates, reconciliación, rotación, TTL/leases, certificados X.509/PKI, keytabs y distribución firmada. Las candidatas de `0.1.0` se publican en [Releases](https://github.com/ml0renz0/secretwright/releases): [notas y alcance](docs/releases/v0.1.0-rc.1.md). El [flujo de releases](docs/features/TBD-releases.md) genera una RC al integrar cambios en `main` y publica la estable al integrar una PR de promoción. La [guía de distribución](docs/distribution.md) explica la verificación de firmas y la instalación, incluidos los [paquetes Debian `.deb`](docs/distribution.md#debian) para amd64 y arm64.

Las operaciones usan el cliente oficial `github.com/hashicorp/vault/api`. `status` lee el estado del servidor sin enviar tokens; `auth check` comprueba el token mediante su endpoint de autoinspección. Los comandos KV utilizan el token seleccionado sin exigir una autoinspección previa.

## Probar con un playground

Con Docker local, Python 3, Go y `make`, prepara un Vault efímero con secretos ficticios, versiones y un AppRole de lectura:

```bash
make playground
source .playground/env.sh
secretwright tree /playground
secretwright cat /playground/apps/payments/database
secretwright shell
# Demo guiada opcional:
make playground-demo
# Al terminar:
make playground-down
unset VAULT_ADDR VAULT_NAMESPACE VAULT_TOKEN
```

El laboratorio usa un [blueprint YAML](examples/playground/blueprint.yaml) para los montajes, la política y el AppRole, y Secretwright para cargar los valores de ejemplo. `env.sh` configura las variables que ya interpreta Secretwright y añade el binario al `PATH`; después usas la CLI directamente. Vault escucha solo en `127.0.0.1` con un puerto libre; las credenciales y el inventario quedan en `.playground/`, fuera de Git. Si ya tienes el binario instalado, puedes arrancar sin Go con `python3 scripts/playground.py up` y cargar el mismo archivo de entorno. La [guía del playground](examples/playground/README.md) explica qué contiene y cómo explorarlo.

## Compilar y ejecutar

Requiere la versión de Go indicada en `go.mod` y `make` para los comandos de desarrollo. El binario resultante no necesita un runtime de Go ni las herramientas de desarrollo instaladas.

```bash
make build
./bin/secretwright --help
./bin/secretwright version

VAULT_ADDR=https://vault.example.com:8200 ./bin/secretwright status
```

Ejecutar `secretwright` sin argumentos abre la shell si hay un terminal interactivo; sin TTY conserva la ayuda. `secretwright shell` inicia una sesión explícita, también desde una tubería o archivo de comandos.

`status` produce JSON con los campos `initialized`, `sealed`, `standby`, `version`, `cluster_name` y `cluster_id`. Su código de salida permite utilizarlo en scripts:

| Código | Significado |
| --- | --- |
| `0` | Vault está inicializado y desellado. |
| `2` | Vault está sellado o no se ha inicializado. |
| `1` | No se ha podido consultar o interpretar el estado. |

Un nodo standby puede estar inicializado y desellado. El código `0` no certifica que el nodo acepte escrituras ni que un token tenga acceso a secretos.

## Shell interactiva y sesiones por lotes

```bash
./bin/secretwright shell --address https://vault.example.com:8200 \
  --token-file /run/secrets/vault-token

# Sin prompt ni eco, con directorio conservado entre líneas.
printf 'cd /secret/app\nls\n' | ./bin/secretwright shell \
  --token-file /run/secrets/vault-token --no-prompt

./bin/secretwright shell --token-file /run/secrets/vault-token \
  --script operations.sw
```

La sesión usa los mismos comandos que la CLI. `cd` cambia su directorio tras comprobarlo; un fallo conserva el anterior. `pwd` devuelve la ruta actual en JSON. El prompt muestra el directorio y el último código de salida en stderr; los resultados siguen saliendo como JSON por stdout.

La dirección, el namespace, el timeout, el archivo de token y `--cwd` se fijan al arrancar la sesión. Esas opciones no pueden cambiarse dentro de ella. Se puede seguir indicando un montaje con `--mount` y `--kv-version` en los comandos que los admiten. La ayuda, el inicio, `pwd` e `history` no consultan Vault ni abren el archivo de token.

Dentro de la shell, `put` exige `--file FILE` y no admite `--file -`: stdin contiene comandos. La CLI directa conserva la entrada JSON por stdin. Por ejemplo, un archivo de sesión puede contener:

```text
cd /secret/app
pwd
put --file database.json database
versions database
exit
```

Tab completa comandos y nombres devueltos por un listado autorizado de Vault; no lee secretos. No ofrece sugerencias si la línea contiene opciones o comillas. Listar un nombre no acredita permiso para leerlo. Ctrl+R busca en el historial aprobado de la sesión: hasta 100 entradas de navegación y consulta, sin archivo en disco. Se excluyen `cat`, autenticación, mutaciones y líneas rechazadas; los valores de los secretos nunca se añaden al historial.

Ctrl+C descarta la línea que se está editando o cancela la operación activa; en modo interactivo conserva la sesión. Ctrl+D con la línea vacía y `exit` terminan con el último código de salida. Los errores permiten continuar en modo interactivo; una sesión por lotes se detiene en el primero. No hay expansión de variables, tuberías, redirecciones ni ejecución de una shell externa.

`secretwright --no-prompt` equivale a una sesión sin prompt y `secretwright --script FILE` lee un archivo de comandos. `--script -` se rechaza; para stdin se usa `shell`. `--file` selecciona archivos de datos de los comandos. El [contrato de F04](docs/features/F04-interactive-shell.md) detalla modos, historial, autocompletado e interrupciones.

## Operaciones recursivas y backup

```bash
./bin/secretwright tree --timeout 1m /secret/app
./bin/secretwright find --file match.json /secret/app
./bin/secretwright replace --file replacement.json --dry-run /secret/app
./bin/secretwright cptree --timeout 1m /secret/app /secret/app-copy
./bin/secretwright backup --file app-backup.json --timeout 1m /secret/app
./bin/secretwright restore --file app-backup.json --dry-run /secret/recovered
```

`tree` recorre nombres mediante LIST y devuelve rutas y tipos en JSON, sin leer secretos. `find` compara el objeto JSON completo de su archivo y devuelve las rutas que coincidan; el orden de las propiedades no importa y los números se comparan sin perder precisión. `replace` recibe un archivo con los objetos `match` y `replacement` y sustituye los objetos completos coincidentes. Los valores nunca se aceptan como argumentos.

`cptree` copia el contenido del directorio conservando las rutas relativas. `rmtree` borra las versiones actuales capturadas, sin destruir historial ni metadatos KV v2; rechaza `/` y las raíces de montajes. Las escrituras y eliminaciones KV v1 exigen `--force`. En KV v2, `replace` usa CAS de la revisión leída y `cptree`/`restore` usan CAS `0`, por lo que no sustituyen claves existentes.

`--dry-run` está disponible en `replace`, `cptree`, `rmtree` y `restore`: muestra la planificación sin mutaciones. Los comandos completan el recorrido, las lecturas y las validaciones antes de escribir. Las operaciones no son atómicas; un fallo tras cambios confirmados o inciertos devuelve `5` con un informe por ruta. No hay rollback ni reintentos automáticos.

El backup contiene los valores actuales en JSON **en texto claro**, se crea con permisos `0600` y nunca sobrescribe un archivo o enlace existente. No guarda tokens, montajes, políticas ni historial. Restore valida todo el archivo antes de contactar con Vault y requiere un destino explícito; no crea montajes. Sus archivos, y los de `find`/`replace`, requieren `--file FILE` y no admiten `-` ni stdin.

`--concurrency` admite entre 1 y 16 tareas, con 4 por defecto; `--timeout` limita la operación completa. Se rechazan recorridos o datos que superen los límites, denegaciones y valores actuales borrados, sin omitirlos silenciosamente. El [contrato de F05](docs/features/F05-advanced-secret-operations.md) especifica el formato del backup, los límites y los informes.

## Accesos e identidades

```bash
./bin/secretwright policy write --token-file admin-token --file app-read.hcl app-read
./bin/secretwright approle write --token-file admin-token --file app-role.json app
./bin/secretwright approle credentials --token-file admin-token --out app-credentials.json app
./bin/secretwright approle login --file app-credentials.json --out app-token
./bin/secretwright token capabilities --token-file app-token secret/data/app/database
./bin/secretwright identity group write --token-file admin-token --file group.json
```

Los grupos `policy`, `approle`, `token` e `identity` administran ACL, roles, credenciales, entidades y grupos internos. Las opciones van después de la acción más específica. AppRole utiliza un montaje de autenticación existente, seleccionable con `--auth-mount`; Secretwright no lo habilita automáticamente.

RoleID, SecretID y tokens se exportan únicamente a archivos nuevos con permisos `0600`; no se muestran en stdout ni se guardan en el historial. Login ignora el token del operador y conserva la sesión actual. Los archivos JSON son estrictos y se validan antes de contactar con Vault; sus campos, límites de TTL y formatos se describen en el [contrato de F06](docs/features/F06-access-identity-management.md).

La creación de tokens exige políticas explícitas y tiempos finitos. Vault conserva la identidad del padre en tokens hijos, por lo que sus permisos derivados de grupos pueden heredarse también. Borrar un SecretID o un rol no revoca los tokens emitidos; `token revoke` y `token revoke-self` requieren `--force` y revocan también descendientes. Las escrituras administrativas no tienen CAS.

Si falla un archivo después de emitir una credencial, se intenta revocarla; una emisión o compensación sin confirmar devuelve `5`, sin volver a emitir automáticamente. Un archivo ya guardado se conserva si falla después el informe de stdout.

## Blueprints YAML

```bash
./bin/secretwright blueprint schema
./bin/secretwright blueprint validate --file examples/blueprints/app.yaml
./bin/secretwright blueprint plan --file examples/blueprints/app.yaml --token-file admin-token
./bin/secretwright blueprint apply --file examples/blueprints/app.yaml --token-file admin-token
```

El motor v1 administra montajes KV, políticas, AppRoles, entidades y grupos internos. El [ejemplo](examples/blueprints/app.yaml) usa variables tipadas y referencias entre recursos; `--vars examples/blueprints/values.yaml` proporciona overrides declarados. Requiere un montaje AppRole existente y permisos administrativos adecuados.

`schema` y `validate` funcionan sin conexión. El esquema versionado se valida localmente y no carga URLs externas. Los planes y resultados contienen metadatos, sin HCL, specs, valores de variables ni credenciales.

Sin `--state`, `apply` conserva las reglas F07: crea lo ausente y conserva lo equivalente. Si un recurso existente difiere, devuelve conflicto sin iniciar escrituras; no actualiza, adopta, elimina ni migra recursos. Después de aplicar, otro plan devuelve `changes: []`. Las operaciones no son atómicas: una aplicación parcial o incierta devuelve `5`, sin rollback ni reintentos automáticos. El [contrato de F07](docs/features/F07-blueprint-engine.md) detalla el formato y las garantías.

## Templates de arquitectura

```bash
./bin/secretwright template list
./bin/secretwright template show single-app
./bin/secretwright template schema
./bin/secretwright template render --file examples/architectures/multi-env.yaml > platform.blueprint.yaml
./bin/secretwright blueprint validate --file platform.blueprint.yaml
# Seleccionar JSON explícitamente.
./bin/secretwright template render --file examples/architectures/multi-env.yaml --format json > platform.blueprint.json
```

El catálogo cubre `single-user`, `multi-user`, `single-app`, `multi-app`, `multi-env` y `saas`. Show y render generan YAML por defecto; `--format json` selecciona JSON. Render funciona offline y produce un blueprint F07 completo para revisar y aplicar después. Cada scope recibe una política propia; las aplicaciones reciben AppRoles y los usuarios entidades y grupos. Los usuarios necesitan un enlace de autenticación externo explícito: render no vincula identidades ni emite credenciales.

Un manifiesto puede componer patrones y compartir un montaje KV v2, manteniendo scopes separados por instancia. El [ejemplo compuesto](examples/architectures/composed-shared-mount.yaml) muestra usuarios y aplicaciones con montaje común. Se rechazan montajes solapados, colisiones y expansiones que superen los 128 recursos. Los ejemplos y el [contrato de F08](docs/features/F08-architecture-templates.md) detallan dimensiones, permisos y límites.

## Reconciliación y drift

```bash
./bin/secretwright blueprint adopt --file examples/reconciliation/base.yaml \
  --state deployment.state.json --token-file operator-token
./bin/secretwright blueprint apply --file examples/reconciliation/base.yaml \
  --state deployment.state.json --token-file operator-token
./bin/secretwright blueprint plan --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token
./bin/secretwright blueprint apply --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token
```

F09 activa la gestión de recursos propios al seleccionar `--state`. `adopt` reclama explícitamente los existentes equivalentes y omite los ausentes, sin escribir en Vault. Apply registra creaciones confirmadas y permite actualizar políticas, AppRoles, entidades y grupos propios. Un recurso externo no se adopta por aparecer como noop. Los recursos retirados del descriptor se retienen; los montajes KV nunca se convierten ni eliminan.

El drift externo se bloquea por defecto. `plan/apply --state ... --repair` autoriza su reconciliación o el reconocimiento de un baseline ya equivalente. Los pending de escrituras inciertas bloquean la operación normal: `blueprint recover --file ... --state ...` consulta y recupera checkpoints locales sin escribir en Vault; una creación incierta existente necesita además `--adopt-pending` para reclamarla.

El inventario privado `0600` contiene metadatos y hashes, sin HCL, specs ni credenciales, y queda ligado a cluster, namespace y dirección configurada. Es una declaración local confiada, sin exclusividad remota. Un lock cooperativo y checkpoints atómicos protegen el archivo; las APIs administrativas de Vault siguen sin CAS. Los [ejemplos de reconciliación](examples/reconciliation/README.md) y el [contrato F09](docs/features/F09-reconciliation-drift.md) detallan las garantías, recuperación y límites.

## Ciclo de vida y rotación

```bash
./bin/secretwright lifecycle example > rotation.yaml
./bin/secretwright lifecycle validate --file rotation.yaml
./bin/secretwright lifecycle rotate --file rotation.yaml \
  --receipt /var/lib/secretwright/app.rotation.yaml --dry-run --token-file operator-token
./bin/secretwright lifecycle rotate --file rotation.yaml \
  --receipt /var/lib/secretwright/app.rotation.yaml --token-file operator-token
# Tras comprobar que la aplicación ha recargado el token nuevo:
./bin/secretwright lifecycle retire --file rotation.yaml \
  --receipt /var/lib/secretwright/app.rotation.yaml --ack-consumer --token-file operator-token
```

La configuración selecciona un AppRole existente, un archivo consumidor privado y una lectura KV v2 para verificar la candidata. Rotate emite y prueba la nueva credencial antes de publicar el archivo atómicamente. La anterior sigue viva hasta retire con confirmación externa. Los recibos guardan metadatos; los secretos de recuperación quedan en artefactos separados `0600`. Recover reconoce checkpoints sin repetir emisión, login, publicación ni revocación.

`lifecycle token inspect|renew` consulta y renueva tokens privados; `lifecycle lease inspect|renew|revoke` gestiona un lease exacto leído de un archivo privado YAML o JSON. Los informes muestran el TTL real concedido. Los comandos son puntuales, aptos para cron o timers externos; no existe un daemon. El [laboratorio de rotación](examples/lifecycle/README.md) y el [contrato F10](docs/features/F10-lifecycle-rotation.md) describen preparación, recuperación y límites.

## Certificados X.509 y PKI

```bash
./bin/secretwright pki example > request.yaml
./bin/secretwright pki validate --file request.yaml
./bin/secretwright pki csr create --file request.yaml --out web.csr --key-out web.key
./bin/secretwright pki sign --mount pki --role web --file request.yaml \
  --csr web.csr --ca-file roots.pem --out web.pem --token-file operator-token
./bin/secretwright pki cert verify --file web.pem --ca-file roots.pem --hostname app.example.test
./bin/secretwright pki cert match --file web.pem --key web.key
```

Los comandos offline inspeccionan certificados, claves y CSR y verifican cadena, tiempo, SAN, usos y correspondencia de clave con las bibliotecas de Go. No necesitan OpenSSL ni acceso a Vault. Las raíces de confianza son explícitas; la verificación local no descarga certificados ni comprueba revocación automáticamente.

Los comandos online leen CA/certificados, emiten una identidad PEM privada, firman una CSR sin enviar su clave y revocan un certificado exacto tras comparar su huella. Requieren un montaje y rol PKI existentes. Las peticiones generadas usan YAML por defecto, con JSON opcional; certificados y claves mantienen PEM. Los [ejemplos](examples/pki/README.md) y el [contrato F11](docs/features/F11-x509-pki.md) explican archivos privados y resultados parciales.

## Kerberos y keytabs

```bash
./bin/secretwright keytab inspect --file service.keytab
./bin/secretwright keytab example > policy.yaml
./bin/secretwright keytab validate --file service.keytab --policy policy.yaml
./bin/secretwright keytab import --file service.keytab --policy policy.yaml \
  --mount secret --path /secret/kerberos/web --token-file operator-token
./bin/secretwright keytab export --mount secret --path /secret/kerberos/web \
  --out recovered.keytab --token-file operator-token
```

El lector Go admite keytabs MIT v2 sin `klist`, muestra principales, KVNO y cifrados sin revelar claves y valida identidades y tipos requeridos mediante una política YAML o JSON. La validación es estructural y de política: no autentica con un KDC ni interpreta el timestamp como caducidad.

Import y export conservan el binario completo mediante un envelope base64 en KV v2. Import usa CAS `0` por defecto y exige una revisión explícita para actualizar; export permite una versión histórica exacta y publica solo archivos nuevos `0600`. Los [ejemplos](examples/keytab/README.md) y el [contrato F12](docs/features/F12-kerberos-keytab.md) explican límites, privacidad y códigos de salida.

## Comprobar autenticación

```bash
# Utilizar VAULT_TOKEN ya proporcionado al proceso.
./bin/secretwright auth check

# Utilizar un archivo de token montado explícitamente.
./bin/secretwright auth check --token-file /run/secrets/vault-token

# Sobrescribir la conexión y seleccionar el namespace raíz.
./bin/secretwright auth check --address https://vault.example.com:8200 \
  --namespace '' --timeout 5s --token-file /run/secrets/vault-token
```

El archivo explícito tiene prioridad sobre `VAULT_TOKEN`. Secretwright no recibe tokens como argumentos, no los guarda automáticamente y no lee `~/.vault-token`. F06 permite exportar credenciales emitidas a un archivo privado elegido con `--out`. El archivo de token admite hasta 64 KiB; se recortan los espacios de los extremos y se rechazan espacios o saltos de línea dentro del token.

`auth check` devuelve JSON con `authenticated`, `namespace`, `policies`, `ttl_seconds` y `renewable`. No muestra el token, su identificador, su accessor ni metadatos arbitrarios de Vault.

| Código | Resultado de `auth check` |
| --- | --- |
| `0` | El token permite consultar `auth/token/lookup-self`. |
| `2` | Falta un token o Vault rechaza la consulta con `401` o `403`. |
| `1` | Error de configuración, transporte, respuesta o salida. |

Una respuesta `403` puede corresponder a un token válido sin permiso de autoinspección. La comprobación no acredita permisos sobre secretos ni sobre otros recursos.

## Leer y navegar secretos KV

Las opciones van antes de la ruta. Se puede utilizar `VAULT_TOKEN` o el mismo archivo explícito de token que admite `auth check`.

```bash
./bin/secretwright mounts --token-file /run/secrets/vault-token
./bin/secretwright ls --token-file /run/secrets/vault-token /
./bin/secretwright ls --token-file /run/secrets/vault-token /secret/app
./bin/secretwright cat --token-file /run/secrets/vault-token /secret/app/database

# Resolver una ruta relativa desde un directorio lógico explícito.
./bin/secretwright cat --cwd /secret/app \
  --token-file /run/secrets/vault-token database
./bin/secretwright cd --cwd /secret/app \
  --token-file /run/secrets/vault-token ..
```

`mounts` devuelve un array JSON de montajes KV visibles, con su ruta y versión. `ls` devuelve los nombres inmediatos ordenados; los directorios terminan en `/`. `cat` devuelve los valores del secreto por stdout en JSON, sin los metadatos de KV v2. Por defecto lee la versión actual; una versión actual borrada se comunica como no encontrada, sin seleccionar otra automáticamente.

`cd` valida el directorio mediante un listado y devuelve su ruta canónica en `{"path":"/secret"}`. En la CLI directa no conserva el directorio entre procesos: usa esa ruta como `--cwd` en la siguiente invocación. La shell mantiene el directorio dentro de la sesión.

Las rutas incluyen el montaje y admiten `.` y `..`. Se normalizan las barras repetidas y no se sale de `/`. F02 rechaza `%`, `\`, `?`, `#`, espacios en blanco y caracteres de control; no hay que codificar las rutas como URL.

El descubrimiento de montajes utiliza los metadatos disponibles para el token, sin exigir acceso administrativo a `sys/mounts`. Si se conoce el montaje, la pareja `--mount` y `--kv-version` evita ese descubrimiento:

```bash
./bin/secretwright cat --mount secret --kv-version 2 \
  --token-file /run/secrets/vault-token /secret/app/database
```

Ambas opciones deben aparecer juntas y la ruta debe pertenecer al montaje indicado. No se adivina una versión cuando Vault deniega el descubrimiento. Poder leer un secreto tampoco garantiza poder listar su directorio.

| Código | Resultado de los comandos KV |
| --- | --- |
| `0` | Consulta satisfactoria. |
| `2` | Falta un token o Vault devuelve `401` o `403`. |
| `3` | Ruta o secreto no encontrado, incluida una versión actual borrada. |
| `4` | Conflicto de versión CAS en una escritura. |
| `5` | Escritura del destino de un movimiento confirmada; borrado del origen sin confirmar. |
| `1` | Error de configuración, ruta, respuesta, transporte o salida. |

El [contrato de F02](docs/features/F02-kv-read-navigation.md) detalla la navegación, los resultados y los escenarios de permisos.

## Escribir, copiar y recuperar versiones

`put` recibe un único objeto JSON no vacío, de hasta 1 MiB, por stdin o desde `--file`. `--file -` también selecciona stdin. Sustituye el objeto completo; no acepta datos `clave=valor` como argumentos.

El cliente conserva los números al interpretar y enviar JSON. El motor KV v2 pasa los datos por `float64`, por lo que Secretwright rechaza antes de escribir cualquier número cuyo valor cambiaría al volver a JSON, también dentro de objetos o arrays. Se admiten, por ejemplo, `0.1`, `1.0` y `9007199254740994`; se rechazan `9007199254740993`, decimales que perderían cifras y valores fuera de rango. El error devuelve `1` y recomienda usar strings para identificadores o cifras de precisión arbitraria, sin convertirlos automáticamente. Esta comprobación se aplica a `put`, `cp`, `mv` y `rollback` con destino KV v2; KV v1 conserva el tratamiento de números de precisión arbitraria.

La limitación está en el [motor KV v2 v0.27.0](https://github.com/hashicorp/vault-plugin-secrets-kv/blob/v0.27.0/path_data.go#L262), incluido en [Vault v2.2.0](https://github.com/hashicorp/vault/blob/v2.2.0/go.mod#L178).

```bash
# En un montaje KV v2, crear una clave sin sobrescribir su historial.
./bin/secretwright put --file database.json /secret/app/database

# Sustituir solo si la versión actual sigue siendo la 3.
./bin/secretwright put --file database.json --cas 3 /secret/app/database

# Leer el JSON de la entrada estándar.
./bin/secretwright put /secret/app/database < database.json
```

En KV v2 el CAS predeterminado es `0`, que solo permite crear una clave sin historial. `--cas N` positivo exige que la versión actual coincida. En KV v1 `put` sustituye los datos directamente y rechaza `--cas`, incluso `0`. No existe `put --force`.

`cp` copia los valores actuales, sin historial. En KV v2 el CAS se aplica al **destino**; en un destino KV v1 se exige `--force` porque no puede condicionarse la sustitución. La pareja `--mount`/`--kv-version` se aplica a ambas rutas: para cruzar montajes se usa el descubrimiento automático.

`mv` confirma la copia antes de borrar el origen. En KV v2 borra solo la revisión capturada al leerlo y conserva una revisión posterior escrita concurrentemente. Un origen KV v1 requiere `--force`, pues su borrado no puede condicionarse. El movimiento no es atómico: si se confirmó la escritura del destino pero no se puede confirmar el borrado del origen, devuelve `5`, conserva el destino y requiere comprobar ambas rutas antes de reintentar. Si la propia escritura del destino pierde su respuesta o devuelve una respuesta inválida, el código es `1`; el destino puede haberse escrito, pero Secretwright no borra el origen.

```bash
./bin/secretwright cp /secret/app/database /secret/app/database-copy
./bin/secretwright mv /secret/app/database-copy /secret/app/database-archived
```

En KV v2, `rm` borra reversiblemente la versión actual o las revisiones indicadas con `--versions`. En KV v1 elimina permanentemente una clave y exige `--force`. No hay borrados recursivos ni eliminación de metadatos.

```bash
./bin/secretwright versions /secret/app/database
./bin/secretwright cat --version 2 /secret/app/database
./bin/secretwright rm --versions 2,3 /secret/app/database
./bin/secretwright undelete --versions 2,3 /secret/app/database
./bin/secretwright rollback /secret/app/database 2
./bin/secretwright destroy --versions 1 --force /secret/app/database
./bin/secretwright rm --force /legacy/app/database
```

Las consultas históricas, `undelete`, `rollback` y `destroy` requieren KV v2. `versions` devuelve revisiones ordenadas con sus fechas y estado, sin valores ni metadatos personalizados. `rollback` crea una **versión nueva** con los datos de la revisión seleccionada y CAS sobre la versión actual; no reescribe el historial. `destroy` destruye permanentemente las revisiones indicadas. Los números de `--versions` deben ser positivos y separarse por comas, sin espacios.

Las escrituras devuelven rutas, versiones y estado de la operación en JSON, sin los valores del secreto. Un error de transporte después de enviar una mutación puede dejar su resultado sin confirmar; Secretwright lo indica y no reintenta automáticamente. El [contrato de F03](docs/features/F03-kv-write-versioning.md) especifica las comprobaciones, conflictos y movimientos parciales.

## Configuración

Configura explícitamente la dirección del servidor; el valor predeterminado es `https://127.0.0.1:8200`. Las opciones van después del comando: `status --timeout 5s` o `auth check --namespace equipo`.

| Variable | Uso |
| --- | --- |
| `VAULT_ADDR` | Dirección HTTP o HTTPS del servidor Vault. |
| `VAULT_AGENT_ADDR` | Dirección opcional de Vault Agent; tiene prioridad sobre `VAULT_ADDR` cuando no se indica `--address`. |
| `VAULT_CACERT` | Archivo PEM de la CA que permite verificar el servidor. |
| `VAULT_CACERT_BYTES` | Certificado o bundle PEM de confianza, suministrado directamente. |
| `VAULT_CAPATH` | Directorio de certificados de CA. |
| `VAULT_CLIENT_CERT` | Certificado PEM de cliente para TLS mutuo. |
| `VAULT_CLIENT_KEY` | Clave privada asociada al certificado de cliente. |
| `VAULT_TLS_SERVER_NAME` | Nombre de servidor que se verificará durante TLS. |
| `VAULT_NAMESPACE` | Namespace de Vault, cuando el servidor lo admita. |
| `VAULT_CLIENT_TIMEOUT` | Límite positivo de tiempo con formato Go, por ejemplo `5s` o `1m`. |
| `VAULT_TOKEN` | Token usado por `auth check` y los comandos KV cuando no se indica `--token-file`. |

`--address` tiene prioridad sobre ambas variables de dirección. `--namespace` tiene prioridad sobre `VAULT_NAMESPACE`, incluso con un valor vacío para seleccionar el namespace raíz. El timeout se resuelve en este orden: `--timeout`, `VAULT_CLIENT_TIMEOUT`, diez segundos. Para la confianza CA se priorizan el archivo, el contenido PEM y el directorio, en ese orden.

El cliente oficial también valida la configuración de entorno. Un `VAULT_CLIENT_TIMEOUT` malformado debe corregirse aunque se use `--timeout`; la configuración TLS del entorno también debe ser válida.

La verificación TLS es obligatoria: `VAULT_SKIP_VERIFY=true` se rechaza. Para una CA interna, proporciona su certificado. El laboratorio utiliza HTTP únicamente en la interfaz local.

Las cabeceras heredadas de `VAULT_HEADERS` no se envían, aunque el cliente oficial valida su formato JSON. `VAULT_WRAP_TTL` tampoco activa el encapsulado de respuestas. `status` continúa sin enviar tokens después de una comprobación de autenticación. Las peticiones no siguen redirecciones ni hacen reintentos automáticos.

## Desarrollo y pruebas

```bash
make fmt
make vet
make test
make build
make check
```

Las pruebas de integración necesitan un servidor Vault real. El laboratorio prepara un servidor efímero y las credenciales temporales de las pruebas:

```bash
make integration-local
```

El laboratorio utiliza Docker o un ejecutable `vault` ya instalado y elimina los recursos que crea al terminar. Con Docker añade PostgreSQL efímero para probar leases renovables y revocación efectiva de acceso SQL; CI exige esta fixture. El fallback local sin Docker señala explícitamente que omite esa parte. Docker o `vault` son requisitos de las pruebas locales, no del binario Secretwright.

`make integration` admite un servidor de desarrollo ya preparado mediante `VAULT_ADDR` y `VAULT_TEST_ROOT_TOKEN_FILE`. El laboratorio usa ese archivo para preparar sus propios tokens, montajes y datos de prueba. Los contratos de [F01](docs/features/F01-connectivity-authentication.md), [F02](docs/features/F02-kv-read-navigation.md), [F03](docs/features/F03-kv-write-versioning.md) y [F04](docs/features/F04-interactive-shell.md) detallan los escenarios.

La CI ejecuta comprobaciones de formato, análisis estático, pruebas unitarias con detector de carreras, compilación, fuzzing de blueprints, arquitecturas, inventarios y rutas, y pruebas de integración contra Vault efímero. Incluye el ejecutable con pseudoterminal para navegación, Tab, Ctrl+R e interrupciones, con capturas privadas. La [guía de pruebas](docs/testing.md) detalla escenarios, comandos de reproducción y límites de cobertura.

## Cómo avanzará el proyecto

Cada fase define primero su contrato funcional y amplía sus escenarios de pruebas y CI antes de implementar la funcionalidad. F00 mantiene deliberadamente pequeño el laboratorio; cada entrega añade las comprobaciones que necesita.

- [Roadmap F00–F13](docs/roadmap.md)
- [Contrato de F00](docs/features/F00-bootstrap.md)
- [Contrato de F01](docs/features/F01-connectivity-authentication.md)
- [Contrato de F02](docs/features/F02-kv-read-navigation.md)
- [Contrato de F03](docs/features/F03-kv-write-versioning.md)
- [Contrato de F04](docs/features/F04-interactive-shell.md)
- [Contrato de F05](docs/features/F05-advanced-secret-operations.md)
- [Contrato de F06](docs/features/F06-access-identity-management.md)
- [Contrato de F07](docs/features/F07-blueprint-engine.md)
- [Contrato de F08](docs/features/F08-architecture-templates.md)
- [Contrato de F09](docs/features/F09-reconciliation-drift.md)
- [Contrato de F10](docs/features/F10-lifecycle-rotation.md)
- [Contrato de F11](docs/features/F11-x509-pki.md)
- [Contrato de F12](docs/features/F12-kerberos-keytab.md)
- [Contrato de F13](docs/features/F13-packaging-release.md)
- [Instalación y verificación de releases](docs/distribution.md)
- [RC y estables desde CI/CD](docs/features/TBD-releases.md)

La planificación conserva el trabajo de diseño de VCLI. El repositorio original permanece como referencia histórica.

## Licencia

[MIT](LICENSE).

La edición de línea utiliza [`chzyer/readline` v1.5.1](https://github.com/chzyer/readline/tree/v1.5.1), una dependencia Go integrada en el binario bajo [licencia MIT](https://github.com/chzyer/readline/blob/v1.5.1/LICENSE).
