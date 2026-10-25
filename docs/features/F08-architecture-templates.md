# F08 — Templates de arquitectura

## Objetivo y límites

Generar blueprints F07 revisables a partir de seis patrones de arquitectura: monousuario, multiusuario, monoapp, multiapp, multientorno y SaaS con varios tenants. Un manifiesto puede componer varios patrones y compartir un montaje KV v2.

F08 genera configuración offline. No consulta Vault, emite credenciales, crea enlaces de autenticación, aplica recursos ni guarda estado. El resultado se valida y aplica mediante los comandos F07; conserva sus reglas de creación, equivalencia y conflicto. La reconciliación, las actualizaciones, el drift y la propiedad de recursos corresponden a F09.

## Comandos

```bash
secretwright template list
secretwright template show single-app
secretwright template schema
secretwright template render --file examples/architectures/multi-env.yaml > platform.blueprint.json

secretwright blueprint validate --file platform.blueprint.json
secretwright blueprint plan --file platform.blueprint.json --token-file operator-token
secretwright blueprint apply --file platform.blueprint.json --token-file operator-token
```

`list` devuelve el catálogo ordenado por nombre, con una descripción de cada patrón. `show NAME` devuelve un manifiesto JSON completo y editable del patrón elegido. `schema` exporta el JSON Schema embebido. `render` escribe por stdout un blueprint JSON F07 completo, con recursos, dependencias y especificaciones.

El único argumento posicional admitido es el nombre de `show`. Render requiere un archivo real con `--file`; no acepta `-`, stdin, `--vars`, parámetros de conexión ni cwd KV. Los cuatro comandos funcionan sin seleccionar un token, crear un cliente Vault ni leer la configuración de conexión heredada. Un error devuelve `1`, con diagnóstico fijo y sin un JSON de éxito parcial. Se detectan también los fallos al escribir la salida.

Los comandos funcionan en la shell con las mismas reglas offline y sin cwd KV. Quedan fuera del historial; el completado ofrece únicamente el nombre raíz `template`, sin completar archivos, valores ni rutas remotas. La redirección del ejemplo pertenece a la shell del sistema operativo, no al lenguaje de la shell interactiva de Secretwright.

La salida de render contiene intencionadamente ACL y configuración para guardarlas y revisarlas. No contiene tokens, RoleID, SecretID ni datos de secretos KV. No es un archivo de plan ejecutable: `blueprint apply` vuelve a consultar y planificar el estado actual.

## Manifiesto y esquema

El manifiesto YAML o JSON contiene solo `api_version`, `name` e `instances`:

```yaml
api_version: secretwright/architecture/v1
name: platform
instances:
  - id: services
    template: multi-env
    mount: platform/kv
    applications: [api, worker]
    environments: [dev, prod]
    auth_mount: approle
    access: read
```

El esquema público es `schemas/architecture-v1.schema.json`, Draft 2020-12, con identificador `urn:secretwright:architecture:v1`. El binario utiliza ese mismo artefacto embebido. No carga esquemas ni referencias externas.

Se reutiliza el lector estricto de F07: un único documento, UTF-8 válido, claves string únicas a cualquier profundidad y números enteros decimales dentro de `int64`. Se rechazan aliases, anchors, merges, tags personalizados, timestamps, binarios, NUL, números flotantes, exponentes y bases alternativas. Los campos desconocidos se rechazan. No hay includes, interpolación, expansión de entorno, funciones ni consultas a secretos.

`name`, los IDs de instancia y las etiquetas de cada dimensión cumplen `^[a-z][a-z0-9-]{0,23}$`. Las listas no admiten valores duplicados. Los montajes KV y AppRole son rutas relativas canónicas válidas según F07; no son URLs ni expresiones glob.

Cada instancia exige `id`, `template` y `mount`, además de las dimensiones de su patrón. `access` es opcional: `read` por defecto o `read-write`. `auth_mount` solo se admite en patrones de aplicación y usa `approle` por defecto. Un campo de dimensión o autenticación que no corresponde al patrón se rechaza; nunca se ignora silenciosamente.

## Catálogo

| Nombre | Dimensiones requeridas | Recursos por scope |
| --- | --- | --- |
| `single-user` | `users`: exactamente un usuario | Política, entidad y grupo interno |
| `multi-user` | `users`: entre 2 y 8 usuarios | Política, entidad y grupo interno |
| `single-app` | `applications`: exactamente una aplicación | Política y AppRole |
| `multi-app` | `applications`: entre 2 y 8 aplicaciones | Política y AppRole |
| `multi-env` | `applications`: 1–8; `environments`: 2–8 | Política y AppRole por combinación |
| `saas` | `tenants`: 2–8; `environments`: 1–8; `applications`: 1–8 | Política y AppRole por combinación |

Cada montaje único añade un recurso KV v2. El producto cartesiano de dimensiones está sujeto al límite total de 128 recursos; que cada lista cumpla su propio límite no implica que una combinación completa quepa en el blueprint.

Los ejemplos editables se distribuyen en `examples/architectures/`: un archivo por patrón y `composed-shared-mount.yaml` para composición. `template show NAME` produce también un ejemplo válido, con nombres ilustrativos y acceso de lectura.

## Ámbitos y permisos

Cada scope tiene una ruta relativa al montaje que incluye el nombre del blueprint y el ID de instancia:

| Patrón | Ruta del scope |
| --- | --- |
| Usuarios | `<name>/<instance>/users/<user>` |
| Monoapp y multiapp | `<name>/<instance>/apps/<app>` |
| Multientorno | `<name>/<instance>/envs/<env>/apps/<app>` |
| SaaS | `<name>/<instance>/tenants/<tenant>/envs/<env>/apps/<app>` |

La política concede permisos sobre la ruta KV v2 de datos exacta del scope y sus descendientes. Con `read`, la capacidad de datos es `read`; con `read-write`, son `create`, `read`, `update` y `delete`. Esta última permite el borrado lógico de datos, sin conceder destrucción de versiones ni administración del montaje.

Para metadatos, la política concede `list` sobre la raíz del scope y `read`/`list` sobre sus descendientes. No concede listado de ancestros ni acceso a otros scopes. Los nombres se validan y las rutas HCL se escriben como strings correctamente entrecomillados, sin interpretar texto como un template.

Los patrones de usuario crean entidades sin políticas directas, habilitadas, y un grupo interno por usuario. El grupo contiene la entidad y la política de su scope. **No crean un método de login ni un alias de autenticación**: el operador debe vincular explícitamente la identidad al método de autenticación que use. El nombre de una entidad no acredita ni enlaza automáticamente a una persona.

Los patrones de aplicación crean un AppRole por scope, asociado solo a su política generada. El montaje AppRole elegido debe existir cuando F07 ejecute plan/apply; render no lo consulta ni lo crea. Los valores fijos son `token_ttl: 15m`, `token_max_ttl: 1h`, `secret_id_ttl: 1h`, `secret_id_num_uses: 1` y `token_num_uses: 0`. Se mantienen SecretID obligatorio, ausencia de política default automática, token service y período cero.

La emisión o el login se realizan después mediante F06, de forma explícita y con salida de credenciales a archivos privados. Render no produce credenciales utilizables.

## Composición y estabilidad

Un manifiesto admite hasta 16 instancias, ordenadas por ID al renderizar. Las etiquetas de cada dimensión se ordenan antes de expandirlas. Reordenar instancias o listas conserva exactamente la misma salida JSON.

Las instancias que declaran el mismo montaje KV v2 comparten un único recurso de montaje. Sus scopes siguen separados por el ID de instancia. Los montajes solapados, como `team` y `team/secrets`, se rechazan. Cualquier otra colisión de recursos generados se considera un error; no se sobrescriben recursos ni se adopta propiedad de ellos.

Los IDs de montaje se derivan de un hash de su ruta. Los IDs de políticas, entidades, grupos y roles se derivan del scope completo. Añadir otro scope conserva los IDs de los existentes; no se basan en la posición de un elemento. Una colisión de hash detectada es un error, no una deduplicación silenciosa.

Los recursos se serializan ordenados por ID en JSON con indentación y salto de línea final. Antes de devolver bytes se valida el blueprint generado con F07, incluidas sus dependencias, nombres, políticas y límites. No se emiten recursos parciales si una instancia falla.

## Límites

| Elemento | Límite |
| --- | --- |
| Archivo de entrada | 1 MiB |
| Profundidad y nodos del lector | 64 niveles y 10 000 nodos |
| Instancias | 1–16 |
| Elementos de cada dimensión | Hasta 8, según la cardinalidad del patrón |
| Recursos del blueprint completo | Hasta 128 |
| Salida generada | Hasta 4 MiB |

Se comprueba el tamaño de las expansiones antes de construir el producto cartesiano. Superar un límite produce error sin truncar ni omitir instancias. Los diagnósticos no reproducen campos, rutas, documentos ni valores rechazados.

## Pruebas de aceptación

El contrato, los ejemplos y las pruebas se publican antes de la implementación. F08 conserva las comprobaciones y regresiones F00–F07 e incorpora:

- Catálogo y ejemplos de los seis patrones, esquema real embebido y render offline utilizable por F07.
- Rechazo de campos desconocidos o inaplicables, duplicados, entradas ambiguas, colisiones, montajes solapados y expansiones fuera de límites.
- Salida canónica determinista y IDs estables al reordenar o añadir scopes.
- Composición con montaje compartido, sin ampliar los permisos entre instancias.
- Contra Vault real, render/plan sin mutaciones, primera aplicación con una creación por recurso, plan posterior vacío y segunda aplicación sin escrituras.
- Permisos efectivos dentro del scope y denegados entre usuarios, apps, entornos y tenants, incluidas etiquetas que son prefijo de otra etiqueta.
- En pruebas de usuarios, aliases creados únicamente por la fixture para demostrar las políticas de grupo; el renderizador no crea esos enlaces.
- CLI y shell offline, historial excluido, errores de salida detectados y ausencia de emisión de credenciales.
- Fuzzing de render con `-race`, presupuesto de 20 segundos y minimización limitada a 100 ms, junto a los objetivos existentes de blueprints y rutas.
