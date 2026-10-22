# F04 — Shell interactiva

## Objetivo

Recuperar la experiencia de shell de VCLI sobre el mismo motor de comandos de F00–F03: directorio lógico de sesión, edición de línea, historial en memoria, autocompletado de rutas y ejecución de sesiones desde stdin o archivo. La búsqueda interactiva de esta fase es la búsqueda del historial con Ctrl+R. `tree`, `find` y las operaciones recursivas pertenecen a F05 del [roadmap](../roadmap.md).

## Inicio y modos de ejecución

```text
secretwright shell [--address URL] [--namespace NAME] [--timeout DURATION]
                   [--token-file FILE] [--cwd PATH] [--no-prompt] [--script FILE]
```

Sin argumentos, el ejecutable abre la shell cuando la entrada y el terminal de salida del prompt son TTY. Sin terminal conserva la ayuda de la CLI. El comando explícito `shell` permite iniciar una sesión desde stdin: con una tubería, sin TTY o con `--no-prompt`, la sesión funciona por lotes, sin prompt, eco ni búsqueda del historial.

`--script FILE` lee comandos desde ese archivo y siempre selecciona el modo por lotes. No admite `-`; para leer stdin se usa `shell`. Las formas superiores `secretwright --no-prompt` y `secretwright --script FILE` seleccionan los mismos modos. El archivo de operaciones se llama `--script`; `--file` sigue siendo la entrada JSON de `put`.

```bash
# Consola con un token proporcionado explícitamente.
secretwright shell --address https://vault.example.com:8200 \
  --token-file /run/secrets/vault-token

# Sesión por lotes desde stdin, conservando el directorio entre líneas.
printf 'cd /secret/app\nls\n' | secretwright shell \
  --token-file /run/secrets/vault-token --no-prompt

# Archivo de comandos, sin prompt ni eco.
secretwright shell --token-file /run/secrets/vault-token --script operations.sw
```

El inicio, la ayuda, `version`, `pwd` e `history` no abren el archivo de token ni consultan Vault. Las conexiones y los permisos se comprueban cuando se ejecuta una operación que los necesita. Los comandos directos de F00–F03 conservan sus opciones, resultados y códigos de salida.

## Estado y comandos de sesión

La sesión conserva un único directorio lógico, inicialmente `/` o el `--cwd` absoluto indicado al arrancar. Su sintaxis se valida sin conexión. `cd` comprueba mediante un listado que el destino sea accesible y solo cambia el directorio si esa operación termina correctamente. Un `cd` fallido conserva el directorio anterior. Las rutas relativas de los demás comandos se resuelven desde él.

Las opciones de dirección, namespace, timeout, archivo de token y directorio inicial se fijan al iniciar la sesión. Dentro de ella se rechazan `--address`, `--namespace`, `--timeout`, `--token-file` y `--cwd`. Así, el autocompletado y la ejecución utilizan el mismo contexto. Se conserva la pareja de montaje explícito `--mount`/`--kv-version` para los comandos KV que la admiten.

| Comando de sesión | Resultado |
| --- | --- |
| `pwd` | JSON `{"path":"/directorio/canónico"}`, sin consultar Vault. |
| `history` | Array JSON de las entradas aprobadas del historial en memoria. |
| `exit` o `quit` | Termina la sesión con el último código de salida; no admite argumentos. |
| Comandos F00–F03 | Ejecutan la misma operación y producen el mismo JSON que la CLI directa. |

No se permite abrir otra shell dentro de una sesión. Las líneas vacías y los comentarios que ocupan una línea completa, cuyo primer carácter significativo es `#`, se omiten.

El prompt tiene la forma `[N] secretwright:/directorio> `: muestra el último código de salida y el directorio, sin token ni valores del secreto. Se escribe en stderr. No hay banner inicial y stdout contiene únicamente los resultados de los comandos; varias consultas pueden producir documentos JSON consecutivos, uno por línea.

### Datos de `put`

Dentro de una sesión, `put` exige `--file FILE` con un nombre no vacío distinto de `-`. No lee JSON del flujo de comandos ni ofrece un prompt de datos multilínea. Esto evita consumir las siguientes líneas como si fueran parte del secreto. En una invocación directa, `secretwright put PATH` y `--file -` conservan su entrada JSON por stdin de F03.

```text
cd /secret/app
pwd
ls
put --file database.json database
versions database
cat --version 1 database
exit
```

`cat` sigue mostrando los valores solicitados en JSON por stdout. Los datos no se convierten en entradas del historial. Se conservan todos los controles de F03: CAS por defecto en KV v2, `--force` donde corresponde, movimientos parciales y rechazo previo de números que perderían precisión al leerlos desde KV v2.

## Edición, interrupciones y errores

La edición de línea admite navegación por el historial aprobado, Tab y búsqueda incremental con Ctrl+R. La biblioteca Go de edición se integra en el binario; no se invoca una shell del sistema ni un programa externo para editar o buscar.

| Situación | Comportamiento |
| --- | --- |
| Error en una sesión interactiva | Muestra el error seguro, actualiza el código del prompt y permite ejecutar el siguiente comando. |
| Primer error en una sesión por lotes | Detiene la sesión y devuelve ese código; no ejecuta las líneas posteriores. |
| EOF o `exit`/`quit` | Devuelve el último código de salida. |
| Ctrl+D con la línea vacía | Termina la sesión. |
| Ctrl+C mientras se edita | Descarta la línea y conserva la sesión. |
| SIGINT durante una operación | Cancela su contexto y registra `130`; en modo interactivo conserva la sesión y en modo por lotes se detiene. |
| Cancelación del contexto de la sesión | Cierra el editor y devuelve `130`. |

Los códigos `0`–`5` de la CLI se conservan. Los errores de lectura, sintaxis o escritura de la sesión devuelven `1`; los mensajes no reproducen la línea rechazada, los argumentos privados ni cuerpos arbitrarios de Vault. El editor restaura el estado del terminal al cerrarse.

### Sintaxis de las líneas

Cada línea contiene un comando. Espacio y tabulador separan argumentos; las comillas simples o dobles los agrupan y la barra inversa permite escapar un carácter. No hay expansión de variables, sustitución de comandos, tuberías, redirecciones ni ejecución de programas externos. Los caracteres `$` y las comillas invertidas se tratan como texto literal. Los operadores `|`, `&`, `;`, `<` y `>` sin comillas se rechazan.

Se exige UTF-8 válido. Las líneas admiten hasta 64 KiB y se rechazan completas si superan ese límite: nunca se ejecuta un prefijo truncado. Comillas sin cerrar, escapes incompletos, NUL, ESC y otros controles no admitidos también producen un error estático. La entrada por lotes admite finales de línea CRLF.

## Historial seguro en memoria

El historial contiene como máximo 100 entradas aprobadas, con deduplicación consecutiva. No hay archivo de historial, carga desde disco ni persistencia entre sesiones. El guardado automático del editor se desactiva antes de leer la primera línea; su historial se reconstruye a partir de las entradas aprobadas, también después de errores, interrupciones y EOF.

Solo se registran comandos que hayan terminado correctamente y cumplan esta lista:

- `help`, `version`, `pwd`, `status` y `mounts`, sin argumentos.
- `ls`, `cd` y `versions`, con cero o una ruta lógica válida y sin opciones.

Se excluyen `cat`, `auth`, todas las mutaciones, `history`, `exit`, comandos desconocidos y líneas inválidas. No se guardan JSON, valores, rutas de archivos de entrada ni argumentos de autenticación. Las entradas aprobadas pueden contener nombres de rutas de Vault: son metadatos de navegación y su presencia en memoria no implica que esos nombres carezcan de sensibilidad.

Ctrl+R busca únicamente en ese historial aprobado. No consulta Vault, no busca valores secretos y no recorre el árbol remoto.

## Autocompletado remoto

Tab completa nombres de comandos y argumentos posicionales simples de rutas de Vault. Funciona al final de la línea y no ofrece candidatos si esta contiene opciones, comillas, escapes u operadores. No completa archivos locales, valores de opciones, credenciales ni números de versión.

Para rutas, resuelve el directorio padre desde el cwd de la sesión y efectúa un único listado autorizado, o consulta el catálogo correspondiente a la raíz. No lee los valores de ningún secreto ni mantiene una caché persistente. Usa la misma dirección, namespace y selección de token que la sesión, con un máximo total de 500 ms para la consulta.

Los resultados se ordenan, se deduplican y se limitan a 100 candidatos que coincidan con el prefijo. Los directorios conservan `/`; al completar comandos o claves se añade un espacio. Las posiciones del cursor y los prefijos se calculan por caracteres Unicode.

Falta de token, denegación o timeout producen una lista vacía de sugerencias, sin diagnósticos ni respuestas del servidor en el prompt. Un nombre devuelto por LIST no demuestra permiso para leer sus datos: listado y lectura siguen siendo permisos independientes.

## Pruebas de aceptación

El contrato, las pruebas y la ampliación de CI preceden a la implementación.

| Escenario | Resultado exigido |
| --- | --- |
| Modos de entrada | TTY interactivo, stdin por lotes, `--no-prompt` y `--script` seleccionan el modo previsto; sin argumentos y sin TTY se conserva la ayuda. |
| Navegación | Un `cd` satisfactorio cambia cwd; un fallo no lo cambia; los comandos posteriores resuelven rutas relativas correctamente. |
| Motor compartido | La sesión conserva los resultados y controles de F00–F03, incluidos CAS, `--force` y números KV v2. |
| Flujo de comandos | `put` sin archivo o con `--file -` falla sin consumir la siguiente línea de la sesión. |
| Sintaxis | Comillas, escapes, UTF-8, CRLF y límites correctos; sin expansión, ejecución externa ni prefijos truncados. |
| Historial | Solo entradas aprobadas, límite y deduplicación; ningún JSON, token, línea rechazada o valor de `cat` entra en la búsqueda. |
| Tab | Listado permitido, rechazo sin token/por ACL, timeout, límite de candidatos y prefijos Unicode; ninguna consulta de datos o archivos locales. |
| Interrupciones | Ctrl+C al editar y durante una petición conserva la sesión; Ctrl+D termina y se restaura el terminal. |
| Errores y salida | Interactivo continúa; lotes se detiene; se respetan códigos, cancelación y fallos de escritura. |
| Vault real | Sesiones con cwd, lectura relativa, `put --file`, permisos y `cd` denegado; se mantienen las comprobaciones de conexión y namespace. |
| Terminal real | Prueba del ejecutable con pseudoterminal para prompt, Tab, Ctrl+R, Ctrl+C y Ctrl+D; capturas privadas sin valores ni credenciales en logs. |

Las pruebas con editor y ejecutor simulados verifican el estado y la cancelación sin depender de un terminal. El laboratorio real comprueba sesiones contra Vault efímero y el ejecutable compilado, incluyendo el modo por lotes y un pseudoterminal. Sus capturas se guardan en archivos privados y se inspeccionan sin publicarlas en logs.

## Ejecución y cierre

```bash
make check
make integration-local
```

F04 se considera validada cuando pasan formato, análisis estático, pruebas con detector de carreras, compilación estática, sesiones con Vault real, pruebas del pseudoterminal y regresión F00–F03. La PR debe distinguir las verificaciones ejecutadas de cualquier comprobación pendiente. El [README](../../README.md) resume el uso de la shell y de la CLI directa.
