# F03 — Escritura y versiones KV

## Objetivo

Ampliar la lectura de [F02](F02-kv-read-navigation.md) con escrituras KV v1/v2, copia, movimiento y recuperación de versiones KV v2. Se conservan la resolución de rutas, la selección de token y las opciones de conexión de F01/F02. Las operaciones son sobre una clave; la recursividad pertenece a F05 del [roadmap](../roadmap.md).

## Contrato funcional

Las opciones van antes de las rutas. Todos los comandos conservan `--address`, `--namespace`, `--timeout`, `--token-file` y `--cwd`. La pareja `--mount`/`--kv-version` permite indicar el montaje y el tipo de motor como en F02.

```text
secretwright put [opciones] [--file FILE] [--cas N] PATH
secretwright rm [opciones] [--versions CSV] [--force] PATH
secretwright cp [opciones] [--cas N] [--force] SOURCE DEST
secretwright mv [opciones] [--cas N] [--force] SOURCE DEST
secretwright versions [opciones] PATH
secretwright cat [opciones] [--version N] PATH
secretwright undelete [opciones] --versions CSV PATH
secretwright destroy [opciones] --versions CSV --force PATH
secretwright rollback [opciones] PATH VERSION
```

### Entrada de datos y escritura

`put` lee JSON de la entrada estándar o del archivo indicado por `--file`. El valor explícito `--file -` selecciona stdin. Se admite exactamente un objeto JSON no vacío, de hasta 1 MiB; JSON malformado, entradas adicionales y otros tipos de valor se rechazan antes de escribir. Los números conservan su precisión. No se aceptan secretos como argumentos `clave=valor` y la ayuda no consume stdin ni carga credenciales.

`put` sustituye el objeto de datos completo, no hace una actualización parcial:

| Destino | Comportamiento |
| --- | --- |
| KV v2, sin `--cas` | Usa CAS `0`: solo crea una clave que todavía no tenga historial. |
| KV v2, `--cas N` positivo | Solo escribe si la versión actual coincide con `N`. |
| KV v1 | Escribe directamente y puede sustituir los datos existentes; no admite `--cas`, tampoco `--cas 0`. |

CAS es la comprobación de versión de Vault. Un CAS obsoleto produce un conflicto y conserva los datos que hubiera en el servidor. `put` no admite `--force`.

```bash
secretwright put --file database.json /secret/app/database
secretwright put --file database.json --cas 3 /secret/app/database
secretwright put /secret/app/database < database.json
```

La salida satisfactoria contiene `path`, `kv_version` y, para KV v2, `version`. No devuelve los valores escritos.

### Borrado de una clave

En KV v2, `rm PATH` hace un borrado reversible de la versión actual; `rm --versions 2,3 PATH` borra reversiblemente esas versiones concretas. No elimina los metadatos ni el historial de la clave. En KV v1 el borrado es permanente, requiere `--force` y no admite `--versions`.

`rm` no es recursivo. La salida contiene `path`, `kv_version` y las versiones explícitas cuando corresponda, sin datos del secreto.

### Copia y movimiento

`cp` lee los valores actuales del origen y los escribe en el destino. No copia el historial ni los metadatos de la clave y puede cruzar montajes o versiones de KV. Se rechazan origen y destino canónicos iguales antes de contactar con Vault.

El CAS de `cp` y `mv` corresponde al **destino**. Un destino KV v2 usa CAS `0` por defecto; `--cas N` permite sustituir únicamente la versión actual esperada. Un destino KV v1 requiere `--force` porque la sustitución no puede condicionarse por versión, y rechaza cualquier `--cas`. `--force` nunca sustituye a CAS en KV v2.

La pareja explícita `--mount`/`--kv-version` se aplica a ambas rutas. Para copiar entre montajes se usa el descubrimiento automático.

`mv` realiza la copia antes de intentar borrar el origen:

- Si falla la escritura del destino, Secretwright no borra el origen.
- En KV v2 borra solo la versión del origen capturada por la lectura. Una versión nueva escrita concurrentemente permanece disponible.
- En KV v1 exige `--force`: el borrado es permanente y no puede comprobar si alguien ha cambiado el origen después de leerlo.
- Si se ha confirmado la escritura del destino y no se puede confirmar el borrado del origen, devuelve el código `5`. Conserva el destino y pide comprobar ambas rutas antes de reintentar; no intenta deshacer la copia silenciosamente. Un timeout al borrar también puede significar que Vault sí aplicó el borrado.

La copia utiliza los valores capturados por su lectura y el movimiento no es una transacción atómica entre rutas. Una modificación concurrente del origen no cambia lo que ya se ha copiado.

Si se pierde la respuesta de la propia escritura del destino o esa respuesta es inválida, el código es `1`: el destino puede haberse escrito, pero no se ha confirmado. Secretwright no borra el origen y el mensaje pide verificar el estado antes de reintentar. El código `5` se reserva al fallo posterior a una copia confirmada.

```bash
secretwright cp /secret/app/database /secret/app/database-copy
secretwright cp --cas 2 /secret/app/database /secret/app/database-copy
secretwright mv /secret/app/database-copy /secret/app/database-archived
```

El resultado satisfactorio contiene `source`, `destination`, `kv_version` del destino, `source_deleted` y las versiones de origen/destino cuando proceda. `source_deleted` es `false` para una copia y `true` cuando el movimiento confirma el borrado. Los valores del secreto no forman parte del resultado.

### Versiones y recuperación KV v2

Estas operaciones requieren un motor KV v2:

| Comando | Efecto |
| --- | --- |
| `versions PATH` | Consulta los metadatos del historial y devuelve las revisiones ordenadas. |
| `cat --version N PATH` | Lee los valores de una revisión positiva concreta. Sin la opción conserva la lectura actual de F02. |
| `undelete --versions CSV PATH` | Recupera exactamente las versiones indicadas que estuvieran borradas reversiblemente. |
| `destroy --versions CSV --force PATH` | Destruye permanentemente las versiones indicadas; no elimina los metadatos de la clave. |
| `rollback PATH VERSION` | Lee esa revisión y crea una versión nueva con sus valores. No reescribe ni elimina el historial anterior. |

`versions` devuelve únicamente `path`, `current_version`, `oldest_version` y un array `versions`. Cada entrada contiene `version`, `created_time`, `deletion_time` y `destroyed`; no se publican valores de secretos ni `custom_metadata`.

Para `rollback` se consulta la versión actual antes de leer los datos históricos y se utiliza ese número como CAS de la nueva escritura. Cualquier escritura concurrente posterior provoca un conflicto en lugar de sobrescribirse. Una revisión destruida o inexistente no se puede restaurar.

`--versions` exige uno o más enteros positivos separados por comas, sin componentes vacíos ni espacios. Se eliminan duplicados y se ordenan los números. `--cas` admite enteros desde cero, mientras que `--version` y el argumento de `rollback` deben ser positivos. `--kv-version` selecciona el tipo de motor, `1` o `2`, no una revisión del secreto.

```bash
secretwright versions /secret/app/database
secretwright cat --version 2 /secret/app/database
secretwright rm --versions 2,3 /secret/app/database
secretwright undelete --versions 2,3 /secret/app/database
secretwright rollback /secret/app/database 2
secretwright destroy --versions 1 --force /secret/app/database
secretwright rm --force /legacy/app/database
```

### Errores y códigos de salida

| Código KV | Resultado |
| --- | --- |
| `0` | Operación satisfactoria. |
| `2` | Falta un token o Vault devuelve `401` o `403`. |
| `3` | Ruta o versión no encontrada, borrada o destruida cuando la operación necesita leer sus datos. |
| `4` | Conflicto CAS o respuesta de conflicto `409`/`412`. |
| `5` | Se confirmó la escritura del destino de un movimiento, pero no el borrado del origen. |
| `1` | Configuración, datos, opciones o respuesta inválida; operación no admitida; transporte, timeout o salida. |

Solo un `400` que identifique el conflicto CAS de Vault se traduce a `4`; otros errores `400` siguen siendo errores generales. Los mensajes no reproducen tokens, valores, argumentos, rutas ni cuerpos arbitrarios del servidor.

Cada operación tiene un único límite de tiempo, que incluye descubrimiento y peticiones posteriores. No hay redirecciones ni reintentos automáticos. Un error de transporte o una respuesta malformada después de enviar una mutación puede dejar el resultado sin confirmar: el mensaje indica que el cambio puede haberse aplicado. Se debe consultar el estado antes de reintentar.

## Pruebas de aceptación

El contrato, las pruebas y la ampliación de CI preceden a la implementación.

| Escenario | Resultado exigido |
| --- | --- |
| JSON de stdin y archivo | Objeto único no vacío, límite de 1 MiB, números grandes exactos y rechazo de datos inválidos sin escrituras. |
| Escritura KV v1/v2 | Payload y ruta API correctos; lectura posterior devuelve exactamente los datos esperados. |
| CAS | Creación exclusiva por defecto; actualización con versión esperada; conflicto obsoleto sin cambiar el valor actual. |
| Opciones y descubrimiento | Rechazo de combinaciones no admitidas, CAS negativo, versiones inválidas y rutas iguales antes de mutar. Una denegación de descubrimiento no provoca una escritura. |
| Permisos | Token con lectura pero sin escritura rechazado; subárbol permitido y subárbol denegado comprobados contra Vault real. |
| Copia | Copia entre montajes y entre KV v1/v2, sin historial ni metadatos arbitrarios, conservando la precisión de los datos. |
| Movimiento | Fallo de copia conserva el origen; origen v2 elimina solo su revisión capturada; fallo posterior a la copia devuelve `5` sin borrar el destino. |
| Historial | Proyección ordenada sin valores ni metadatos personalizados. Lectura histórica y rechazo en KV v1. |
| Recuperación | Borrado reversible, recuperación exacta, destrucción forzada y rollback que crea una versión nueva mediante CAS. |
| Transporte | No se repiten mutaciones tras timeout, redirección o error; los resultados inciertos se comunican sin exponer datos. |
| CLI y regresión | Resultados de mutación sin valores, códigos de salida correctos y prueba privada del ejecutable con stdin/archivo. F00–F02 siguen pasando. |

El laboratorio Vault real amplía sus montajes, tokens limitados y datos temporales para verificar escrituras, conflictos, copia, borrado y recuperación. La prueba del ejecutable captura las salidas en archivos privados y comprueba los valores sin publicarlos en los logs. La limpieza del laboratorio se conserva incluso cuando falla un escenario.

## Ejecución y cierre

```bash
make check
make integration-local
```

F03 se considera validada cuando pasan formato, análisis estático, pruebas con detector de carreras, compilación, integración con Vault real, prueba del ejecutable y regresión F00–F02. La PR debe identificar los resultados ejecutados y las comprobaciones pendientes. El [README](../../README.md) resume los comandos.
