# Secretwright

Shell interactiva y gestión declarativa del ciclo de vida de secretos para HashiCorp Vault.

Secretwright nace como una reescritura en Go de [VCLI](https://github.com/ml0renz0/vcli). El objetivo es conservar su experiencia de shell y distribuir un único binario, incorporando progresivamente gestión de accesos, blueprints componibles, reconciliación y rotación de credenciales.

## Estado del proyecto

**F00–F02 están integradas**: base Go, conexión, comprobación de tokens y lectura/navegación KV v1/v2. **F03 añade escritura, copia, movimiento e historial KV v2** en la [PR #4](https://github.com/ml0renz0/secretwright/pull/4), pendiente de merge. La shell interactiva, los blueprints y la rotación pertenecen a fases posteriores.

Las operaciones usan el cliente oficial `github.com/hashicorp/vault/api`. `status` lee el estado del servidor sin enviar tokens; `auth check` comprueba el token mediante su endpoint de autoinspección. Los comandos KV utilizan el token seleccionado sin exigir una autoinspección previa.

## Compilar y ejecutar

Requiere la versión de Go indicada en `go.mod` y `make` para los comandos de desarrollo. El binario resultante no necesita un runtime de Go ni las herramientas de desarrollo instaladas.

```bash
make build
./bin/secretwright --help
./bin/secretwright version

VAULT_ADDR=https://vault.example.com:8200 ./bin/secretwright status
```

Ejecutar `secretwright` sin argumentos muestra la ayuda. La shell interactiva se incorporará en F04.

`status` produce JSON con los campos `initialized`, `sealed`, `standby`, `version`, `cluster_name` y `cluster_id`. Su código de salida permite utilizarlo en scripts:

| Código | Significado |
| --- | --- |
| `0` | Vault está inicializado y desellado. |
| `2` | Vault está sellado o no se ha inicializado. |
| `1` | No se ha podido consultar o interpretar el estado. |

Un nodo standby puede estar inicializado y desellado. El código `0` no certifica que el nodo acepte escrituras ni que un token tenga acceso a secretos.

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

El archivo explícito tiene prioridad sobre `VAULT_TOKEN`. Secretwright no recibe tokens como argumentos, no los guarda y no lee `~/.vault-token`. El archivo admite hasta 64 KiB; se recortan los espacios de los extremos y se rechazan espacios o saltos de línea dentro del token.

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

`cd` valida el directorio mediante un listado y devuelve su ruta canónica en `{"path":"/secret"}`. No conserva el directorio entre procesos: usa esa ruta como `--cwd` en la siguiente invocación. La shell de F04 mantendrá el directorio dentro de la sesión.

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

El laboratorio utiliza Docker o un ejecutable `vault` ya instalado y elimina los recursos que crea al terminar. No descarga automáticamente herramientas en el equipo. Docker o `vault` son requisitos de las pruebas locales, no del binario Secretwright.

`make integration` admite un servidor de desarrollo ya preparado mediante `VAULT_ADDR` y `VAULT_TEST_ROOT_TOKEN_FILE`. El laboratorio usa ese archivo para preparar sus propios tokens, montajes y datos de prueba. Los contratos de [F01](docs/features/F01-connectivity-authentication.md), [F02](docs/features/F02-kv-read-navigation.md) y [F03](docs/features/F03-kv-write-versioning.md) detallan los escenarios.

La CI ejecuta comprobaciones de formato, análisis estático, pruebas unitarias, compilación y pruebas de integración contra Vault efímero.

## Cómo avanzará el proyecto

Cada fase define primero su contrato funcional y amplía sus escenarios de pruebas y CI antes de implementar la funcionalidad. F00 mantiene deliberadamente pequeño el laboratorio; cada entrega añade las comprobaciones que necesita.

- [Roadmap F00–F13](docs/roadmap.md)
- [Contrato de F00](docs/features/F00-bootstrap.md)
- [Contrato de F01](docs/features/F01-connectivity-authentication.md)
- [Contrato de F02](docs/features/F02-kv-read-navigation.md)
- [Contrato de F03](docs/features/F03-kv-write-versioning.md)

La planificación conserva el trabajo de diseño de VCLI. El repositorio original permanece como referencia histórica.

## Licencia

[MIT](LICENSE).
