# F00 — Bootstrap y CI/CD Base

## Objetivo

Crear el incremento mínimo de Secretwright que se pueda compilar y comprobar contra un Vault real. F00 establece la CLI, una consulta de estado de solo lectura y el laboratorio de pruebas. El resto del [roadmap](../roadmap.md) se incorpora por fases.

## Contrato funcional

### CLI

- `secretwright` y `secretwright --help` muestran la ayuda sin conectarse a Vault.
- `secretwright version` muestra la versión del ejecutable sin conectarse a Vault.
- `secretwright status` consulta el estado del servidor mediante el cliente oficial `github.com/hashicorp/vault/api`.
- Los comandos desconocidos y los errores se comunican por la salida de error con un código distinto de cero.
- El binario no necesita un runtime de Go ni ejecutar `curl`, `jq`, Python u otras herramientas para consultar Vault.

La entrada sin argumentos muestra ayuda hasta que F04 incorpore la shell interactiva.

### Estado de Vault

`status` consulta el endpoint de salud de Vault. La respuesta JSON expone únicamente:

| Campo | Tipo | Significado |
| --- | --- | --- |
| `initialized` | Booleano | El servidor está inicializado. |
| `sealed` | Booleano | El servidor está sellado. |
| `standby` | Booleano | El nodo opera como standby. |
| `version` | Cadena | Versión del servidor. |
| `cluster_name` | Cadena | Nombre del clúster, si está disponible. |
| `cluster_id` | Cadena | Identificador del clúster, si está disponible. |

| Situación | Código de salida |
| --- | --- |
| Inicializado y desellado, incluido standby | `0` |
| Sellado o sin inicializar | `2` |
| Error de configuración, transporte o respuesta | `1` |

Los estados sellado y sin inicializar deben producir información de estado aunque Vault utilice un código HTTP distinto de `200`. Los errores de transporte o respuesta no se convierten en un resultado satisfactorio.

La consulta de salud no requiere un token y no demuestra permisos de lectura o escritura sobre secretos. Las pruebas de autenticación pertenecen a F01.

### Configuración y seguridad

- Se utiliza la configuración estándar de conexión de Vault, incluida la dirección, la confianza CA y, cuando corresponda, el certificado de cliente y el namespace.
- La verificación TLS permanece activada.
- El laboratorio de desarrollo puede utilizar HTTP en loopback; sus recursos son efímeros.
- La consulta no crea, modifica ni elimina recursos Vault.
- La ayuda, la versión y la salida de estado no incluyen credenciales.

## Pruebas de aceptación

Las pruebas unitarias utilizan servidores HTTP controlados para verificar el contrato de la CLI y la interpretación de respuestas, incluidos los estados sellado y sin inicializar. Deben comprobar también que los fallos de transporte y las respuestas inválidas se devuelven como errores.

Las pruebas de integración se ejecutan contra un Vault real de desarrollo:

1. Preparar el servidor efímero y esperar a que esté disponible con un límite de tiempo.
2. Ejecutar la consulta de estado a través del código de Secretwright.
3. Comprobar que Vault está inicializado y desellado, y que la respuesta contiene su versión.
4. Propagar los fallos de la prueba como código de salida distinto de cero.
5. Eliminar el servidor y los recursos temporales creados por el laboratorio, también cuando falle una prueba.

El laboratorio local admite Docker o un ejecutable `vault` ya instalado. No descarga automáticamente herramientas. También se pueden ejecutar las pruebas contra un servidor local existente mediante `VAULT_ADDR`.

## Comandos de desarrollo

| Comando | Finalidad |
| --- | --- |
| `make build` | Compilar `bin/secretwright`. |
| `make fmt` | Aplicar formato al código Go. |
| `make vet` | Ejecutar el análisis estático de Go. |
| `make test` | Ejecutar las pruebas unitarias. |
| `make integration` | Ejecutar las pruebas contra el Vault indicado en `VAULT_ADDR`. |
| `make integration-local` | Preparar Vault efímero, ejecutar las pruebas y limpiar. |
| `make check` | Ejecutar las comprobaciones locales de calidad. |

## CI

GitHub Actions debe comprobar formato, análisis estático, pruebas unitarias, compilación y la primera prueba de integración contra Vault efímero. El laboratorio comienza con una única versión fijada de Vault; las matrices y escenarios adicionales se incorporarán cuando una fase los necesite.

## Criterio de cierre

F00 se considera terminada cuando el proyecto compila, las comprobaciones unitarias y estáticas pasan, y la integración contra Vault real se ha ejecutado con éxito. La documentación debe distinguir los resultados ejecutados de las verificaciones pendientes por limitaciones del entorno.

La shell, la gestión KV, IAM, los blueprints, la reconciliación, la rotación, PKI y Kerberos se implementan en fases posteriores. F00 no establece una arquitectura extensa para funciones que aún no se han desarrollado.
