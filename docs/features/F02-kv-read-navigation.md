# F02 — Lectura y navegación KV v1/v2

## Objetivo

Añadir lectura y navegación de secretos KV sobre la conexión y autenticación de [F01](F01-connectivity-authentication.md). Los comandos del producto utilizan únicamente consultas `GET` y `LIST`. La escritura y el historial de versiones pertenecen a F03; la shell interactiva, a F04 del [roadmap](../roadmap.md).

## Contrato funcional

```text
secretwright mounts [opciones de conexión y token]
secretwright ls [opciones] [PATH]
secretwright cat [opciones] PATH
secretwright cd [opciones] [PATH]
```

Las opciones van antes de la ruta. Se conservan `--address`, `--namespace`, `--timeout` y `--token-file`, con las precedencias y validaciones de F01. La ayuda de cada comando funciona sin conexión ni token.

`ls`, `cat` y `cd` añaden `--cwd PATH`, que selecciona el directorio lógico de esta invocación y por defecto es `/`. También admiten la pareja `--mount PATH --kv-version 1|2` para indicar explícitamente el montaje y su versión.

### Resultados

| Comando | Resultado JSON |
| --- | --- |
| `mounts` | Array ordenado de montajes KV visibles: `{"path":"secret/","version":2}`. Los montajes anidados conservan su ruta completa. |
| `ls` | Array ordenado y sin duplicados de nombres inmediatos; los directorios terminan en `/`. Sin ruta, lista `.`. |
| `cat` | Objeto con los valores del secreto. En KV v2 devuelve el objeto de datos interior, sin el envoltorio de metadatos. |
| `cd` | Objeto `{"path":"/directorio/canónico"}` después de comprobar que el directorio puede listarse. Sin ruta, selecciona `/`. |

`cat` muestra los valores del secreto por la salida estándar. F02 lee únicamente la versión actual; un secreto KV v2 cuya versión actual esté borrada devuelve «no encontrado», sin recuperar una versión anterior.

La raíz y los directorios que agrupan montajes anidados son directorios virtuales. Por ejemplo, un montaje `team/kv/` aparece como `team/` al listar `/` y como `kv/` al listar `/team`.

### Navegación

Las rutas son lógicas e incluyen el montaje: `/secret/app/database`. Una ruta relativa se resuelve desde `--cwd`. Se admiten `.` y `..`, las barras repetidas se normalizan y la navegación no sale de `/`. El directorio indicado por `--cwd` debe ser absoluto.

La ruta canónica comienza por `/` y no termina en barra, salvo la propia raíz. F02 rechaza `%`, `\`, `?`, `#`, espacios en blanco y caracteres de control; no interpreta escapes de URL. Los demás nombres Unicode se conservan.

`cd` no conserva el directorio entre ejecuciones del programa. Su salida permite obtener una ruta validada y usarla como `--cwd` en la siguiente invocación. La conservación del directorio dentro de una sesión llegará con la shell de F04.

```bash
secretwright ls --token-file /run/secrets/vault-token /
secretwright ls --cwd /secret --token-file /run/secrets/vault-token app
secretwright cat --cwd /secret/app --token-file /run/secrets/vault-token database
secretwright cd --cwd /secret/app --token-file /run/secrets/vault-token ..
```

Poder leer un secreto no implica poder listar su directorio. `cd` exige que la consulta de listado del destino sea satisfactoria.

### Descubrimiento de montajes

El catálogo usa `sys/internal/ui/mounts` y el descubrimiento de una ruta utiliza `sys/internal/ui/mounts/<ruta>`, mediante el cliente oficial. Se filtran los montajes KV y se distingue v1 de v2 por sus metadatos. No se exige acceso administrativo a `sys/mounts` ni se hace una autoinspección del token antes de leer KV.

La operación no adivina KV v1 cuando falla el descubrimiento. Vault también devuelve `403` cuando no existe un montaje coincidente, para ocultar su inventario. Por eso, solo el listado puede consultar el catálogo tras un `403` o `404`: devuelve un directorio virtual únicamente si el catálogo visible demuestra que es un ancestro estricto de montajes KV y no está dentro de otro montaje KV visible. Sin esa prueba se conserva el error original. Nunca se consulta un backend después de un fallo de descubrimiento.

Si se indica `--mount`, también debe indicarse `--kv-version`, y viceversa. La pareja evita el descubrimiento automático, pero la ruta solicitada debe seguir perteneciendo a ese montaje. La pertenencia se comprueba por segmentos: `secret/` no incluye `secretary/`.

```bash
secretwright cat --mount secret --kv-version 2 \
  --token-file /run/secrets/vault-token /secret/app/database
```

La lectura KV v1 utiliza la ruta del montaje y la clave. En KV v2 se consulta `data/` para leer y `metadata/` para listar. Un segmento lógico llamado `data` sigue siendo parte del nombre de la clave; no se confunde con un prefijo de la API. Los motores distintos de KV y las versiones no admitidas producen un error.

### Códigos de salida

| Código de los comandos KV | Resultado |
| --- | --- |
| `0` | Consulta satisfactoria. |
| `2` | Falta un token o Vault devuelve `401` o `403`. |
| `3` | La ruta o el secreto no existe, incluida una versión actual borrada. |
| `1` | Configuración o ruta inválida, respuesta malformada, motor no admitido, transporte, timeout o error de salida. |

Los códigos y resultados de `status` y `auth check` se conservan. Los errores no reproducen tokens, valores de secretos, rutas solicitadas ni cuerpos de error arbitrarios del servidor.

## Pruebas de aceptación

El contrato y los escenarios de CI preceden a la implementación.

| Escenario | Resultado exigido |
| --- | --- |
| KV v1 y KV v2 | Listado y lectura con las rutas API correspondientes; valores correctos y sin envoltorio de metadatos v2. |
| Montajes anidados | Descubrimiento por la ruta completa y navegación de directorios virtuales. |
| Resolución de rutas | Rutas absolutas y relativas, `.` y `..`, normalización, raíz y rechazo de entradas no admitidas. |
| Montaje explícito | Pareja montaje/versión obligatoria; evita el descubrimiento y no permite salir del montaje. |
| Permisos independientes | Listar no concede lectura y leer no concede listado. Se comprueban accesos permitidos y denegados con tokens limitados. |
| Fallo de descubrimiento | No se adivina una versión ni se intenta leer datos después de una denegación. |
| Ausencia y borrado | Se distingue una ruta no encontrada de un fallo de acceso; no se recuperan versiones anteriores. |
| Respuestas inválidas | Metadatos de montaje, envoltorios y arrays de claves malformados fallan sin publicar su contenido. |
| Aislamiento | Tokens y namespaces permanecen en su operación; las consultas concurrentes no contaminan `status`. |
| Transporte | Se mantienen TLS verificado, timeout, cancelación y ausencia de redirecciones. |
| CLI | Ayuda sin conexión, opciones, JSON, códigos de salida y errores de escritura correctos. |
| Regresión | F00 y F01, formato, análisis estático, detector de carreras y compilación siguen pasando. |

El laboratorio real prepara montajes KV v1/v2, un montaje anidado y datos de prueba con su credencial administrativa efímera. Los escenarios del producto usan tokens limitados para comprobar subárboles permitidos y denegados, listado y lectura, claves llamadas `data` y borrado de la versión actual en KV v2. La prueba del ejecutable captura los datos de `cat` en archivos privados de la fixture y los comprueba sin escribir sus valores en los logs.

Solo el laboratorio provisiona y elimina recursos para las pruebas; los comandos de F02 no escriben secretos. La selección de namespace se verifica en las peticiones HTTP. El laboratorio Community Edition no acredita aislamiento entre namespaces Enterprise.

## Ejecución y cierre

```bash
make check
make integration-local
```

El laboratorio mantiene la limpieza del servidor, montajes, tokens y archivos temporales incluso si falla una prueba. La ejecución contra un servidor de desarrollo existente sigue usando `VAULT_ADDR` y `VAULT_TEST_ROOT_TOKEN_FILE`; esa credencial permite al laboratorio preparar sus propios escenarios.

F02 se considera validada cuando pasan los escenarios unitarios y de integración con Vault real, la prueba del ejecutable y la regresión F00/F01. La PR debe distinguir los resultados ejecutados de cualquier comprobación pendiente. El [README](../../README.md) resume el uso de los comandos.
