# Secretwright

Shell interactiva y gestión declarativa del ciclo de vida de secretos para HashiCorp Vault.

Secretwright nace como una reescritura en Go de [VCLI](https://github.com/ml0renz0/vcli). El objetivo es conservar su experiencia de shell y distribuir un único binario, incorporando progresivamente gestión de accesos, blueprints componibles, reconciliación y rotación de credenciales.

## Estado del proyecto

La primera entrega, **F00**, establece el proyecto Go, una CLI mínima, la consulta de estado de Vault y las pruebas que acompañarán al desarrollo. La shell interactiva, las operaciones KV, los blueprints y la rotación pertenecen a fases posteriores y todavía no están disponibles.

La consulta `status` usa el cliente oficial `github.com/hashicorp/vault/api`. Lee el estado del servidor; no escribe recursos ni comprueba los permisos de un usuario. La autenticación y la gestión completa de conexiones corresponden a F01.

## Compilar y ejecutar

Requiere la versión de Go indicada en `go.mod` y `make` para los comandos de desarrollo. El binario resultante no necesita un runtime de Go ni las herramientas de desarrollo instaladas.

```bash
make build
./bin/secretwright --help
./bin/secretwright version

VAULT_ADDR=https://vault.example.com:8200 ./bin/secretwright status
```

Ejecutar `secretwright` sin argumentos muestra la ayuda durante F00. La shell interactiva se incorporará en F04.

`status` produce JSON con los campos `initialized`, `sealed`, `standby`, `version`, `cluster_name` y `cluster_id`. Su código de salida permite utilizarlo en scripts:

| Código | Significado |
| --- | --- |
| `0` | Vault está inicializado y desellado. |
| `2` | Vault está sellado o no se ha inicializado. |
| `1` | No se ha podido consultar o interpretar el estado. |

Un nodo standby puede estar inicializado y desellado. El código `0` no certifica que el nodo acepte escrituras ni que un token tenga acceso a secretos.

## Configuración

La conexión utiliza las variables estándar de Vault. Configura explícitamente la dirección del servidor; el valor predeterminado del cliente es `https://127.0.0.1:8200`.

| Variable | Uso |
| --- | --- |
| `VAULT_ADDR` | Dirección HTTP o HTTPS del servidor Vault. |
| `VAULT_CACERT` | Archivo PEM de la CA que permite verificar el servidor. |
| `VAULT_CAPATH` | Directorio de certificados de CA. |
| `VAULT_CLIENT_CERT` | Certificado PEM de cliente para TLS mutuo. |
| `VAULT_CLIENT_KEY` | Clave privada asociada al certificado de cliente. |
| `VAULT_TLS_SERVER_NAME` | Nombre de servidor que se verificará durante TLS. |
| `VAULT_NAMESPACE` | Namespace de Vault, cuando el servidor lo admita. |

La verificación TLS está activada. Para una CA interna, proporciona su certificado en lugar de desactivar la verificación. El modo de desarrollo del laboratorio utiliza HTTP únicamente en la interfaz local.

## Desarrollo y pruebas

```bash
make fmt
make vet
make test
make build
make check
```

Las pruebas de integración necesitan un servidor Vault real. Para utilizar un servidor de desarrollo existente:

```bash
VAULT_ADDR=http://127.0.0.1:8200 make integration
```

Para ejecutar las pruebas con un Vault efímero gestionado por el laboratorio:

```bash
make integration-local
```

El laboratorio utiliza Docker o un ejecutable `vault` ya instalado y elimina los recursos que crea al terminar. No descarga automáticamente herramientas en el equipo. Docker o `vault` son requisitos de las pruebas locales, no del binario Secretwright.

La CI ejecuta comprobaciones de formato, análisis estático, pruebas unitarias, compilación y pruebas de integración contra Vault efímero.

## Cómo avanzará el proyecto

Cada fase define primero su contrato funcional y amplía sus escenarios de pruebas y CI antes de implementar la funcionalidad. F00 mantiene deliberadamente pequeño el laboratorio; cada entrega añade las comprobaciones que necesita.

- [Roadmap F00–F13](docs/roadmap.md)
- [Contrato de F00](docs/features/F00-bootstrap.md)

La planificación conserva el trabajo de diseño de VCLI. El repositorio original permanece como referencia histórica.

## Licencia

[MIT](LICENSE).
