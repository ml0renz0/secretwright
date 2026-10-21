# F01 — Conexión y autenticación a Vault

## Objetivo

Ampliar la base de [F00](F00-bootstrap.md) con configuración explícita de conexión y comprobación de autenticación por token. El producto conserva sus consultas de solo lectura y el binario autocontenido. La shell, KV, gestión de AppRoles y blueprints se incorporan en fases posteriores del [roadmap](../roadmap.md).

## Contrato funcional

```text
secretwright status [--address URL] [--namespace NAME] [--timeout DURATION]
secretwright auth check [--address URL] [--namespace NAME] [--timeout DURATION]
                       [--token-file PATH]
```

Las opciones van después del comando o subcomando. La ayuda, la versión, `status --help` y `auth check --help` funcionan sin conectarse ni validar credenciales. La entrada sin argumentos conserva la ayuda de F00.

### Conexión

| Ajuste | Prioridad, de mayor a menor |
| --- | --- |
| Dirección | `--address`, `VAULT_AGENT_ADDR`, `VAULT_ADDR`, `https://127.0.0.1:8200`. |
| Namespace | `--namespace`, `VAULT_NAMESPACE`, namespace raíz. |
| Timeout | `--timeout`, `VAULT_CLIENT_TIMEOUT`, diez segundos. |

Un valor explícito de dirección anula también `VAULT_AGENT_ADDR`. `--namespace ''` selecciona el namespace raíz aunque el entorno indique otro. Los timeouts tienen formato de duración Go, como `5s` o `1m`, y deben ser positivos. Un contexto cancelado o con un plazo más corto termina antes la operación.

La dirección efectiva debe ser una URL HTTP o HTTPS absoluta con host, sin credenciales, query ni fragmento. Las consultas no siguen redirecciones ni hacen reintentos automáticos.

TLS siempre verifica al servidor. Se conservan `VAULT_CACERT`, `VAULT_CACERT_BYTES` y `VAULT_CAPATH`, con prioridad en ese orden; `VAULT_CLIENT_CERT` y `VAULT_CLIENT_KEY` configuran TLS mutuo y deben suministrarse juntos. `VAULT_TLS_SERVER_NAME` permite indicar el nombre TLS esperado. `VAULT_SKIP_VERIFY=true` se rechaza.

### Fuente del token

`auth check` utiliza el archivo indicado por `--token-file` o, si no existe esa opción, `VAULT_TOKEN`. Un archivo explícito no recurre al entorno si no puede leerse. El límite de lectura es 64 KiB; se recortan los espacios de los extremos y se rechaza el espacio en blanco dentro del token.

Secretwright no admite el valor del token como argumento, no lee `~/.vault-token`, no mantiene una sesión persistente y no escribe credenciales. Un archivo montado de solo lectura es válido.

### Comprobación de autenticación

La operación hace `GET /v1/auth/token/lookup-self` mediante el cliente oficial de Vault. Devuelve únicamente:

| Campo JSON | Tipo | Contenido |
| --- | --- | --- |
| `authenticated` | Booleano | `true` después de una autoinspección válida. |
| `namespace` | Cadena | Namespace seleccionado; vacío para la raíz. |
| `policies` | Array de cadenas | Políticas devueltas por la autoinspección. |
| `ttl_seconds` | Entero | TTL restante en segundos; puede ser cero. |
| `renewable` | Booleano | Si Vault declara que el token puede renovarse. |

No se publican token, `id`, `accessor` ni metadatos arbitrarios de la respuesta. Una respuesta malformada no se interpreta como autenticación satisfactoria.

| Código de salida de `auth check` | Resultado |
| --- | --- |
| `0` | Autoinspección válida. |
| `2` | Falta un token o Vault devuelve `401` o `403`. |
| `1` | Error de configuración, transporte, timeout, respuesta o salida. |

Un `403` puede indicar que un token válido carece de permiso de autoinspección. El resultado no acredita permisos sobre KV ni sobre otros recursos de Vault.

`status` conserva su JSON y códigos de salida: `0` para inicializado y desellado, `2` para sellado o sin inicializar, `1` para errores. Nunca envía un token, tampoco después de llamar a `auth check` en el mismo proceso. Las cabeceras de `VAULT_HEADERS` se ignoran en ambas operaciones; solo se añaden las cabeceras propias necesarias y el token seleccionado para la autoinspección.

Los errores no reproducen valores de credenciales, argumentos rechazados, rutas de archivos de token ni cuerpos de error arbitrarios enviados por el servidor.

## Pruebas de aceptación

Las pruebas y CI se amplían antes de implementar la funcionalidad.

| Escenario | Resultado exigido |
| --- | --- |
| Token válido | Una sola autoinspección autenticada; JSON limitado a los campos contratados. |
| Token ausente, inválido o revocado | Fallo con código `2`, sin credenciales en salida. |
| Respuesta `401` o `403` | Error de autenticación reconocible, sin copiar el cuerpo remoto. |
| Fuentes de token | El archivo explícito prevalece; límites, lectura y formato se validan sin guardar el token. |
| Opciones y entorno | Precedencias correctas, incluido namespace raíz explícito y dirección que anula Vault Agent. |
| TLS y TLS mutuo | CA no confiada rechazada; CA configurada y pareja de cliente correcta aceptadas. |
| Timeout y cancelación | La consulta termina dentro del límite y conserva la causa de cancelación. |
| Aislamiento de credenciales | Tokens y cabeceras no pasan a `status` ni a otras comprobaciones concurrentes. |
| Argumentos y salida | Ayuda sin conexión, errores sin valores sensibles y fallos de escritura propagados. |
| Regresión F00 | Ayuda, versión, health, estados de Vault, formato, análisis estático y build siguen pasando. |

El laboratorio de integración crea un Vault real efímero y sus propios tokens de prueba. Comprueba aceptación de un token válido y rechazo de tokens inválidos o revocados, además del funcionamiento del ejecutable compilado. Las operaciones del producto no leen ni escriben secretos KV; el laboratorio crea y revoca únicamente las credenciales de sus escenarios.

La selección del namespace se comprueba en las peticiones HTTP. El laboratorio Community Edition no acredita aislamiento entre namespaces Enterprise.

## Ejecución y cierre

```bash
make check
make integration-local
```

El laboratorio elimina el servidor y los archivos temporales de credenciales, también cuando falla una prueba. Para usar un servidor de desarrollo ya preparado, `make integration` requiere `VAULT_ADDR` y `VAULT_TEST_ROOT_TOKEN_FILE`, que contiene la credencial de administración de ese laboratorio.

F01 se considera validada cuando pasan las comprobaciones unitarias, estáticas y de compilación, la integración con Vault real y la regresión F00. Los resultados ejecutados y las comprobaciones pendientes deben distinguirse en la PR. El [README](../../README.md) resume el uso del producto.
