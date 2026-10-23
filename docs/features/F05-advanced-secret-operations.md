# F05 — Operaciones avanzadas sobre secretos

## Objetivo

Incorporar `tree`, `find`, `replace`, `cptree`, `rmtree`, `backup` y `restore` sobre los motores KV v1/v2 existentes. Se conserva el comportamiento útil de VCLI: `find` compara un objeto JSON completo y `replace` sustituye el objeto completo cuando coincide. Los valores se proporcionan mediante archivos y nunca mediante argumentos.

La implementación comparte la conexión, la resolución de rutas y los controles de F00–F04. No administra montajes, políticas ni identidades. El backup contiene valores actuales; no es una copia de seguridad del servidor Vault ni de su historial.

## Comandos

```text
secretwright tree [options] [PATH]
secretwright find --file MATCH.json [options] [PATH]
secretwright replace --file RULE.json [--force] [--dry-run] [options] [PATH]
secretwright cptree [--force] [--dry-run] [options] SOURCE DEST
secretwright rmtree [--force] [--dry-run] [options] PATH
secretwright backup --file OUTPUT.json [options] PATH
secretwright restore --file INPUT.json [--force] [--dry-run] [options] DEST
```

Las opciones preceden a las rutas. Se admiten las opciones de conexión y selección KV habituales: `--address`, `--namespace`, `--timeout`, `--token-file`, `--cwd` y la pareja `--mount`/`--kv-version`. `--concurrency N` controla el número de operaciones simultáneas, entre 1 y 16; el valor predeterminado es 4. `--timeout` limita la operación completa, incluida su planificación.

En `tree`, `find` y `replace`, PATH vale `.` si se omite. Las rutas de origen representan directorios; un secreto que tenga exactamente el mismo nombre que el directorio raíz no forma parte del recorrido. Los demás comandos requieren rutas explícitas. Los archivos de entrada y salida exigen un nombre real mediante `--file`: no se admite `-` ni se consume stdin, tampoco en la CLI directa.

```bash
secretwright tree --timeout 1m /secret/app
secretwright find --file match.json /secret/app
secretwright replace --file replacement.json --dry-run /secret/app
secretwright cptree --timeout 1m /secret/app /secret/app-copy
secretwright backup --file app-backup.json --timeout 1m /secret/app
secretwright restore --file app-backup.json --dry-run /secret/recovered
```

## Recorrido y búsqueda

`tree` hace exclusivamente listados autorizados. Devuelve un objeto JSON con `root` y `entries`; cada entrada contiene su ruta absoluta canónica `path` y un booleano `directory`. La raíz no se repite en las entradas. Las entradas se ordenan de forma determinista.

En Vault pueden coexistir el secreto `foo` y el directorio `foo/` con una clave `foo/bar`. El recorrido conserva ambas entradas y distingue su tipo; no convierte las rutas en nombres de archivos locales. El árbol puede mostrar claves cuya versión actual esté borrada, porque LIST devuelve nombres sin leer los valores.

Un montaje vacío cuya raíz haya sido comprobada mediante descubrimiento automático produce un árbol vacío. La misma respuesta `404` en un subdirectorio o en un montaje explícito sin comprobar sigue siendo un error; no se ocultan denegaciones.

`find --file MATCH.json` lee todos los valores actuales del subárbol y devuelve únicamente las rutas que coincidan con el objeto del archivo. El orden de las propiedades no altera la comparación; los números se comparan sin convertirlos a `float64`, de modo que `1` y `1.0` son equivalentes sin confundir enteros grandes distintos. No se buscan subcadenas, claves aisladas ni versiones históricas.

La coincidencia vacía es un array JSON vacío con código `0`. La falta de permiso, un secreto desaparecido o una versión actual borrada producen un error; no se presentan como una búsqueda completa sin coincidencias. La lectura de valores requiere permisos adicionales a LIST.

## Reemplazo y operaciones recursivas

El archivo de `replace` tiene exclusivamente dos campos: `match` y `replacement`, ambos objetos JSON no vacíos. Los datos reales deben prepararse en un archivo privado; el siguiente ejemplo describe su estructura:

```json
{
  "match": {"setting": "previous"},
  "replacement": {"setting": "next"}
}
```

Solo se reemplazan objetos que coincidan completamente. Si el objeto de sustitución ya es equivalente al actual, se informa `unchanged` y no se crea otra revisión.

`cptree SOURCE DEST` copia el contenido de SOURCE conservando las rutas relativas bajo DEST, sin añadir otro nivel con el nombre del origen. No copia historial ni elimina secretos del origen. Se rechazan rutas iguales o solapadas por ascendencia, comparando segmentos completos.

`rmtree PATH` elimina las versiones actuales capturadas durante la planificación. No admite `/`, ancestros virtuales de montajes ni la raíz de un montaje. En KV v2 usa el endpoint de borrado de revisiones concretas: una revisión posterior creada concurrentemente se conserva. El borrado es reversible y no elimina metadatos; por ello LIST puede seguir mostrando esos nombres. En KV v1 la eliminación es permanente y exige `--force`.

Antes de cualquier mutación se completa el recorrido, la lectura de los valores actuales, la resolución de todos los destinos y la validación numérica. Si esa planificación falla, no se inicia ninguna escritura. El conjunto no es una transacción ni una instantánea consistente de Vault: otros clientes pueden modificarlo durante el proceso.

| Operación | Protección de escritura |
| --- | --- |
| `replace` en KV v2 | CAS de la revisión capturada al leer; una modificación posterior causa conflicto. |
| `cptree` y `restore` en KV v2 | CAS `0`, solo creación; una clave con historial, incluso borrada, entra en conflicto. |
| Escritura o borrado en KV v1 | Requiere `--force`; Vault no ofrece CAS para esas operaciones. |

Se conservan las restricciones numéricas de F03 para cualquier destino KV v2. Una sustitución o copia con números que perderían precisión se rechaza durante la planificación, antes de escribir otros elementos. KV v1 conserva los números JSON de precisión arbitraria.

`--dry-run` ejecuta la planificación y devuelve sus rutas y estados sin escribir ni borrar. No acredita permisos de escritura futuros, ausencia de conflictos posteriores ni atomicidad. No hay archivos de plan reutilizables ni reintentos automáticos.

## Backup y restore

`backup` reúne todos los valores actuales antes de publicar el archivo final. Usa JSON versionado, con esta estructura:

```text
{
  "format": "secretwright-kv",
  "version": 1,
  "root": "/secret/app",
  "entries": [
    {"path": "database", "data": { ... }},
    {"path": "nested/item", "data": { ... }}
  ]
}
```

El archivo contiene secretos en texto claro y se crea con permisos `0600`. La publicación es exclusiva: un archivo o enlace ya existente se conserva y provoca un error. Se usa un archivo temporal privado en el mismo directorio y se publica después de completar la lectura, codificación y escritura; los fallos previos no dejan un backup final incompleto. stdout recibe solo `root` y el número de entradas.

No se incluyen tokens, dirección del servidor, políticas, metadatos personalizados, revisiones anteriores ni información para crear montajes. Si algún valor actual no puede leerse, incluso por borrado, la operación falla sin publicar un backup incompleto como si fuera satisfactorio.

`restore` valida el archivo completo antes de cargar credenciales o contactar con Vault: formato y versión, campos permitidos, miembros JSON duplicados, límites, objetos de datos, rutas relativas canónicas y rutas exactas duplicadas. Se rechazan rutas absolutas, `.`/`..`, barras repetidas y texto lógico inválido. `foo` y `foo/bar` son claves distintas y válidas.

DEST selecciona explícitamente la raíz de restauración. El campo `root` del archivo es informativo y no cambia la conexión ni el destino. Cada clave se resuelve mediante la configuración actual; no se crean montajes ni se confía en selectores de backend procedentes del archivo. Los destinos KV v2 son de solo creación; KV v1 exige `--force`. No se restaura el historial original.

## Límites, errores y salida

| Recurso | Límite |
| --- | --- |
| Entradas del recorrido, incluidos directorios | 10 000 |
| Profundidad relativa | 64 niveles |
| Objeto de un secreto o archivo de búsqueda/regla | 1 MiB |
| Datos acumulados durante la planificación | 32 MiB |
| Archivo de backup/restore completo | 32 MiB |
| Concurrencia | 1–16, predeterminada 4 |

Superar un límite provoca un error sin truncar silenciosamente los resultados. Las denegaciones y los errores de listado no se omiten. Todas las tareas iniciadas terminan antes de devolver el resultado o limpiar el token del cliente.

Las mutaciones devuelven un informe JSON ordenado con `operation`, `root`, `destination` cuando corresponda, `dry_run` e `items`. Los elementos contienen rutas, revisión cuando corresponda y estados `planned`, `unchanged`, `written`, `deleted`, `failed`, `unconfirmed` o `not_started`. Los errores de elementos usan categorías estáticas. No contienen valores, reglas, fragmentos de archivos ni respuestas arbitrarias de Vault.

Tras el primer error de ejecución se deja de enviar trabajo nuevo y se espera a las tareas en curso. El informe conserva los resultados confirmados y los resultados inciertos; no hay rollback automático. El código `5` indica una operación incompleta con cambios confirmados o una mutación cuyo resultado no se puede confirmar. Hay que comprobar el estado antes de reintentar.

Si no hubo cambios ni resultados inciertos, se conserva el código subyacente: `2` por autenticación/permisos, `3` por ruta no encontrada, `4` por conflicto y `1` por configuración, formato, límites, transporte o salida. La cancelación sin cambios devuelve `130`. Un error de planificación no publica un informe de mutaciones parciales.

## Integración con la shell

Los comandos utilizan la conexión fija y el directorio de la sesión. Sus archivos nunca consumen las siguientes líneas del flujo de comandos. Solo `tree` sin opciones puede entrar en el historial aprobado como consulta de navegación; `find`, `replace`, `cptree`, `rmtree`, `backup` y `restore` quedan excluidos.

Tab añade los nombres de los siete comandos y completa únicamente posiciones de rutas lógicas simples. Se mantiene la política de F04: no se completa una línea con opciones, comillas o escapes, ni se consultan archivos locales o valores de secretos.

## Pruebas de aceptación

El contrato y las pruebas se publican antes de la implementación. La validación exige formato, vet, módulos bloqueados, pruebas con detector de carreras, compilación estática y regresión F00–F04, además de:

- Recorridos LIST sin lecturas, montajes anidados, claves y directorios del mismo nombre, orden estable y límites sin truncado.
- Coincidencia JSON completa con números exactos y sin exposición de datos en resultados, errores o historial.
- Denegación o valor borrado durante la planificación sin escrituras ni backup final.
- CAS de reemplazo, copia/restauración de solo creación y borrado de la revisión capturada ante modificaciones concurrentes.
- Concurrencia acotada, deadline total, cancelación y resultados parciales deterministas sin reintentos.
- Archivo privado exclusivo, rechazo de archivos/enlaces existentes, validación offline íntegra y conservación de precisión al restaurar.
- Sesiones contra Vault real y pruebas del ejecutable para los siete comandos, con capturas privadas y comprobación de valores sin publicarlos en logs.
