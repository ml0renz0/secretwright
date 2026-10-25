# F07 — Motor de blueprints

## Objetivo y límites de la fase

Describir recursos de Vault en YAML, validarlos mediante un JSON Schema versionado y ejecutar `validate`, `plan` y `apply` con variables y dependencias. El motor reutiliza los controles de conexión y acceso de F00–F06.

F07 admite cinco tipos de recursos: montajes KV, políticas ACL, AppRoles, entidades y grupos internos. Crea recursos ausentes y acepta los existentes equivalentes. Una configuración existente distinta o incompatible produce un conflicto antes de escribir. No actualiza, adopta, elimina ni migra recursos automáticamente. La propiedad, el drift y la reconciliación pertenecen a F09; los templates de arquitectura y su composición pertenecen a F08.

Un blueprint no contiene datos de secretos KV, tokens, RoleID, SecretID ni operaciones de emisión. No hay estado local persistente ni archivos de plan ejecutables. La creación de credenciales sigue siendo una operación explícita de F06.

## Comandos

```bash
secretwright blueprint schema
secretwright blueprint validate --file examples/blueprints/app.yaml
secretwright blueprint plan --file examples/blueprints/app.yaml --token-file admin-token
secretwright blueprint apply --file examples/blueprints/app.yaml --token-file admin-token
```

`schema` exporta el esquema embebido. `validate` comprueba el documento, las variables y el grafo sin cargar credenciales, crear un cliente Vault ni consultar la red. Ambos funcionan aunque la configuración de conexión heredada sea inválida.

`plan` y `apply` admiten `--address`, `--namespace`, `--timeout` y `--token-file`. El timeout limita la operación completa. Las opciones van después de la acción y no hay argumentos posicionales. `--file` y el opcional `--vars` requieren archivos reales; no se admite `-`, stdin, includes ni lectura de archivos indicada desde el documento. No se usa el cwd lógico KV de una shell.

`apply` vuelve a leer el estado y calcula un plan nuevo. No ejecuta una salida anterior de `plan`, no solicita confirmaciones interactivas ni reintenta escrituras automáticamente.

## Descriptor y JSON Schema

El documento tiene `api_version: secretwright/v1`, `name`, `variables` opcional y un array `resources`. Cada recurso contiene `id`, `kind`, `name`, `spec` y `depends_on` opcional. El [ejemplo de aplicación](../../examples/blueprints/app.yaml) muestra los cinco tipos y una dependencia de grupo a entidad.

```yaml
api_version: secretwright/v1
name: ${var.prefix}
variables:
  prefix: {type: string, default: demo-app}
resources:
  - id: storage
    kind: kv_mount
    name: ${var.prefix}
    spec: {version: 2}
  - id: read_policy
    kind: policy
    name: ${var.prefix}-read
    depends_on: [storage]
    spec:
      policy: |
        path "${var.prefix}/data/app/*" { capabilities = ["read"] }
```

El esquema publicado es `schemas/blueprint-v1.schema.json`, con identificador `urn:secretwright:blueprint:v1` y Draft 2020-12. El binario utiliza ese mismo archivo embebido para validar en tiempo de ejecución. No carga esquemas, referencias ni metadatos desde URLs o archivos externos; las referencias del esquema son internas.

La raíz del esquema valida el documento después de resolver las variables. El fragmento `#/$defs/envelope` valida la estructura inicial de una plantilla; después de expandirla, el motor aplica el esquema completo y las comprobaciones semánticas. Para validar un archivo con `${var.NAME}`, utiliza `blueprint validate`, que realiza ambos pasos.

Se rechazan campos desconocidos, tipos incorrectos, nombres inválidos y documentos con claves duplicadas, incluso dentro de los recursos. YAML y JSON pasan por el mismo lector. No se admiten anchors, aliases, merges, tags personalizados, timestamps, binarios, claves de mapa no string ni varios documentos. Los números deben ser enteros decimales dentro de `int64`; no se admiten exponentes, flotantes ni bases alternativas antes de validar el esquema.

La validación incluye la sintaxis HCL de las políticas y los controles tipados de F06. La validación semántica final de ACL y las autorizaciones siguen dependiendo de Vault; `validate` no acredita acceso al servidor.

## Variables

Se declaran hasta 64 variables con tipo `string`, `integer` o `boolean` y un `default` opcional del mismo tipo. Un default `0` o `false` cuenta como valor. Una variable sin default debe recibir un valor en el archivo `--vars`, que contiene un mapa de nombres declarados a valores del tipo correspondiente.

```yaml
# values.yaml
prefix: payments-dev
auth_mount: approle
secret_uses: 3
```

```bash
secretwright blueprint validate --file examples/blueprints/app.yaml --vars values.yaml
```

La forma exacta `${var.NAME}` conserva el tipo de la variable; por ejemplo, puede proporcionar un entero a `secret_id_num_uses`. La interpolación dentro de una cadena, como `${var.prefix}-read`, solo admite variables string. Se sustituye una sola vez, sin reevaluar el contenido de un override.

Solo se expanden nombres de blueprint, nombres de recursos y valores string dentro de `spec`. Los IDs, tipos, claves de mapas y dependencias permanecen estáticos. No hay expresiones, funciones, expansión de entorno, shell ni consultas a secretos. Las variables representan configuración no secreta; sus valores y las especificaciones expandidas no se incluyen en los informes.

## Tipos de recursos

| Tipo | Especificación admitida y comportamiento |
| --- | --- |
| `kv_mount` | `version: 1` o `2`. Crea un montaje KV ausente; acepta el mismo tipo y versión. Rechaza conversiones, migraciones, tuning, raíces reservadas y solapamientos de montajes. |
| `policy` | `policy` contiene HCL. Se compara su sintaxis formateada, sin prometer equivalencia general de reglas reordenadas. No se modifica `root`. |
| `approle` | Campos tipados de F06 y `auth_mount` opcional, por defecto `approle`. El montaje de autenticación debe existir y ser AppRole. Se comparan también SecretID obligatorio, ausencia de default automático, tipo service y período cero. |
| `entity` | `policies` y `disabled`; el nombre proviene del recurso. Se localiza por nombre y se conserva su ID. |
| `group` | Políticas, IDs de miembros y referencias lógicas `member_entities`/`member_groups`. Solo grupos internos; las referencias se convierten a UUID después de encontrar o crear sus dependencias. |

Los nombres de recursos y políticas se exigen en minúsculas para impedir colisiones por normalización de Vault. Los montajes admiten rutas relativas canónicas de segmentos. No se acepta un selector de conexión, token o namespace dentro del blueprint.

El motor consulta catálogos administrativos para probar el tipo y existencia de los montajes; el operador necesita los permisos de lectura y creación correspondientes. No confunde un `404` de rol con un montaje AppRole inexistente. Las lecturas de entidades y grupos se hacen por nombre, sin recorrer todas las identidades ni guardar un mapa persistente de IDs.

## Dependencias y planificación

Los IDs de recursos son únicos. `depends_on` referencia IDs del documento. Las referencias de miembros de grupos añaden sus dependencias automáticamente y deben apuntar al tipo correcto. Se rechazan referencias desconocidas, dependencias propias, ciclos, destinos duplicados después de expandir variables y montajes declarados solapados.

El orden es topológico y determinista, con desempate por ID. Todas las lecturas y validaciones de la planificación se completan antes de iniciar cualquier escritura. Las denegaciones y respuestas inválidas no se omiten ni se presentan como un plan completo.

El JSON de `plan` contiene `blueprint`, `resources` y `changes`. Los recursos muestran ID lógico, tipo, nombre, acción y una categoría de motivo cuando corresponde. Las acciones son `create`, `noop` y `conflict`; `changes` excluye los noops. No se incluyen HCL, specs, variables, estados completos ni credenciales. Un plan con conflictos se devuelve con código `4`, sin escrituras.

Después de un `apply` satisfactorio, un nuevo `plan` debe devolver `changes: []`. Un segundo `apply` no realiza escrituras sobre recursos equivalentes. Si una configuración existente difiere, se conserva y se informa del conflicto; no se atribuye propiedad del recurso al blueprint.

## Aplicación, carreras y fallos parciales

`apply` ejecuta en orden topológico y conserva en memoria los UUID necesarios para los grupos dependientes. Antes de cada recurso vuelve a comprobar existencia, ID y fingerprint de los campos administrados. Si el estado observado cambió, detiene la aplicación; tampoco adopta una creación concurrente aunque parezca equivalente.

Las comprobaciones previas no son CAS: las APIs administrativas de Vault no ofrecen una operación atómica de comparación y escritura. Otra operación puede intervenir entre la lectura y la escritura. Se verifica también el resultado después de crear, y una verificación fallida se considera un resultado que puede haber aplicado cambios.

El informe de aplicación contiene solo metadatos y estados `created`, `unchanged`, `conflict`, `failed`, `unconfirmed` o `not_started`. Tras el primer fallo no se envían más mutaciones. Los cambios ya realizados se conservan; no hay rollback automático.

Si hubo una creación confirmada o una escritura incierta antes del error, se devuelve `5`. Hay que comprobar el estado antes de volver a ejecutar. Si no hubo cambios, se conserva el error de permisos, conflicto, configuración o cancelación. No se genera un archivo de recuperación con valores sensibles.

## Límites y códigos

| Recurso | Límite |
| --- | --- |
| Archivo YAML/JSON de blueprint o variables | 1 MiB cada uno |
| Recursos | 1–128 |
| Variables | 64; string de hasta 4096 bytes |
| Profundidad y nodos YAML | 64 niveles; 10 000 nodos |
| Documento expandido | 4 MiB |
| Cadena individual y HCL | 128 KiB |

Superar un límite produce un error sin truncar el documento. Los mensajes no reproducen fragmentos YAML, valores de variables, HCL ni diagnósticos arbitrarios de librerías o de Vault.

Los códigos son `0` por éxito, `1` por documento/configuración/transporte/salida inválidos, `2` por autenticación o permisos, `3` por prerrequisito no encontrado, `4` por conflicto y `5` por aplicación parcial o incierta. La cancelación sin cambios devuelve `130`.

En la shell se conserva la conexión para `plan` y `apply`, sin cwd KV. `schema` y `validate` siguen offline incluso con un token de inicio inaccesible. Todos los comandos blueprint quedan fuera del historial y del completado de archivos o valores remotos.

## Pruebas de aceptación

Contrato y pruebas se publican antes de la implementación. La fase exige formato, vet, módulos bloqueados, pruebas con `-race`, compilación estática y regresión F00–F06, además de:

- Esquema real embebido, YAML estricto, límites, variables tipadas de una pasada, referencias y orden topológico.
- Ningún dato de specs, variables o credenciales en planes, resultados o errores.
- Preflight completo sin escrituras ante denegaciones, conflictos o tipos incompatibles.
- UUID de dependencias resueltos al aplicar; cambios concurrentes y resultados inciertos detenidos sin reintentos.
- Aplicación contra Vault real seguida de plan vacío y segunda aplicación sin cambios.
- Recursos de acceso utilizables con credenciales emitidas después mediante F06, con permisos concedidos y denegados.
- Ejecución del binario y validación del ejemplo distribuido, también sin conexión y desde la shell.
