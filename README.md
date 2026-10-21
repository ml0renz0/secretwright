# Secretwright

Shell interactiva y gestión declarativa del ciclo de vida de secretos para HashiCorp Vault.

Secretwright nace como una reescritura en Go de [VCLI](https://github.com/ml0renz0/vcli). El objetivo es conservar su experiencia de shell y distribuir un único binario, incorporando progresivamente gestión de accesos, blueprints componibles, reconciliación y rotación de credenciales.

## Estado del proyecto

**F00 está integrada** y establece el proyecto Go, una CLI mínima, la consulta de estado de Vault y el laboratorio de pruebas. **F01 está en desarrollo** y añade comprobación de autenticación por token y opciones de conexión. La shell interactiva, las operaciones KV, los blueprints y la rotación pertenecen a fases posteriores.

Las consultas usan el cliente oficial `github.com/hashicorp/vault/api`. `status` lee el estado del servidor sin enviar tokens; `auth check` comprueba el token mediante su endpoint de autoinspección. Ambos comandos son de solo lectura.

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
| `VAULT_TOKEN` | Token usado únicamente por `auth check` cuando no se indica `--token-file`. |

`--address` tiene prioridad sobre ambas variables de dirección. `--namespace` tiene prioridad sobre `VAULT_NAMESPACE`, incluso con un valor vacío para seleccionar el namespace raíz. El timeout se resuelve en este orden: `--timeout`, `VAULT_CLIENT_TIMEOUT`, diez segundos. Para la confianza CA se priorizan el archivo, el contenido PEM y el directorio, en ese orden.

El cliente oficial también valida la configuración de entorno. Un `VAULT_CLIENT_TIMEOUT` malformado debe corregirse aunque se use `--timeout`; la configuración TLS del entorno también debe ser válida.

La verificación TLS es obligatoria: `VAULT_SKIP_VERIFY=true` se rechaza. Para una CA interna, proporciona su certificado. El laboratorio utiliza HTTP únicamente en la interfaz local.

Las cabeceras heredadas de `VAULT_HEADERS` no se envían, aunque el cliente oficial valida su formato JSON. `status` continúa sin enviar tokens después de una comprobación de autenticación. Ninguna de estas consultas sigue redirecciones ni hace reintentos automáticos.

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

`make integration` admite un servidor de desarrollo ya preparado mediante `VAULT_ADDR` y `VAULT_TEST_ROOT_TOKEN_FILE`. Las pruebas de autenticación necesitan ese archivo para crear y revocar sus propios tokens de prueba. El contrato de [F01](docs/features/F01-connectivity-authentication.md) detalla los escenarios.

La CI ejecuta comprobaciones de formato, análisis estático, pruebas unitarias, compilación y pruebas de integración contra Vault efímero.

## Cómo avanzará el proyecto

Cada fase define primero su contrato funcional y amplía sus escenarios de pruebas y CI antes de implementar la funcionalidad. F00 mantiene deliberadamente pequeño el laboratorio; cada entrega añade las comprobaciones que necesita.

- [Roadmap F00–F13](docs/roadmap.md)
- [Contrato de F00](docs/features/F00-bootstrap.md)
- [Contrato de F01](docs/features/F01-connectivity-authentication.md)

La planificación conserva el trabajo de diseño de VCLI. El repositorio original permanece como referencia histórica.

## Licencia

[MIT](LICENSE).
