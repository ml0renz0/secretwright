# F09 — Reconciliación y drift

## Objetivo y compatibilidad

Comparar el estado deseado de un blueprint con sus recursos administrados, detectar cambios externos y aplicar actualizaciones explícitas sin borrar recursos implícitamente. La reconciliación utiliza un inventario local privado que contiene metadatos de propiedad y fingerprints; no guarda especificaciones, HCL, variables ni credenciales.

Los comandos F07 `blueprint plan` y `blueprint apply` **sin `--state` conservan su comportamiento** de creación, equivalencia o conflicto. F09 se activa al seleccionar un archivo de estado. Los blueprints y templates F08 mantienen su formato.

F09 no implementa eliminaciones, unmount, tune, migraciones KV, renombrados, rotación, emisión de secretos, marcadores remotos de propiedad ni archivos de plan ejecutables. El inventario es una declaración local confiada del operador; no es una prueba de propiedad exclusiva en Vault ni un lock distribuido entre operadores.

## Flujo de uso

```bash
# Reclamar explícitamente los recursos existentes equivalentes.
# Los ausentes se omiten: un servidor limpio puede iniciar un inventario vacío.
secretwright blueprint adopt --file examples/reconciliation/base.yaml \
  --state deployment.state.json --token-file operator-token

# Crear los recursos ausentes y registrar solo creaciones confirmadas.
secretwright blueprint plan --file examples/reconciliation/base.yaml \
  --state deployment.state.json --token-file operator-token
secretwright blueprint apply --file examples/reconciliation/base.yaml \
  --state deployment.state.json --token-file operator-token

# Modificar explícitamente la configuración deseada de los recursos propios.
secretwright blueprint plan --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token
secretwright blueprint apply --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token
```

`adopt` consulta Vault y crea un archivo de estado nuevo con permisos `0600`. No modifica recursos remotos. Registra únicamente recursos existentes que coinciden con el blueprint; omite los ausentes. Un recurso diferente, incompatible o inaccesible rechaza toda la adopción y no produce un archivo de inventario satisfactorio. Un archivo o symlink ya existente nunca se sobrescribe.

Durante `apply`, un recurso existente equivalente sin registro propio es externo: puede aparecer como `noop`, pero no adquiere propiedad silenciosamente. Si difiere, produce conflicto. Un recurso ausente sin registro puede crearse y adquirir propiedad únicamente después de verificar la escritura y guardar su checkpoint.

`plan --state` solo lee: no crea locks, no actualiza fingerprints y no escribe archivos. `apply --state` vuelve a planificar bajo un lock exclusivo del inventario; no ejecuta una planificación guardada o recibida desde otro proceso.

## Cambios deseados y externos

El baseline es el fingerprint de los campos administrados observados en la última creación, actualización, adopción o recuperación confirmada. La planificación distingue los siguientes casos:

| Recurso observado | Resultado |
| --- | --- |
| Propio, sin cambios respecto al baseline y equivalente al descriptor | `noop` |
| Propio, sin cambios externos, pero diferente del nuevo estado deseado | `update`, motivo `desired_change` |
| Propio, fingerprint diferente del baseline | Drift; conflicto por defecto |
| Externo y equivalente | `noop`, sin adquirir propiedad |
| Externo y diferente | Conflicto |
| Propio desaparecido o con identidad reemplazada | Conflicto, incluso con `--repair` |
| Registrado, pero retirado del descriptor | `retain`, sin lectura ni mutación remota |

El drift de campos administrados exige `--repair` para reconciliarlo. Esto evita sustituir automáticamente una modificación externa, aunque el blueprint no haya cambiado:

```bash
secretwright blueprint plan --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --repair --token-file operator-token
secretwright blueprint apply --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --repair --token-file operator-token
```

Con `--repair`, un recurso propio diferente puede actualizarse con motivo `external_drift`. Si ya coincide con el estado deseado pero cambió respecto al baseline, `refresh` reconoce el nuevo baseline mediante una escritura local; no modifica Vault. Sin `--repair`, ese reconocimiento también queda bloqueado.

Los recursos retenidos aparecen en el informe, pero no en `changes`. Permanecen registrados y no se comprueba su drift mientras estén fuera del descriptor. Una lista `changes: []` significa que no hay acciones pendientes sobre el descriptor actual; no acredita el estado remoto de recursos retenidos.

Cambiar tipo, nombre o montaje AppRole de un ID registrado produce conflicto. Un ID nuevo puede crear otro recurso mientras el anterior queda retenido. No hay renombrado ni reemplazo implícito.

## Campos administrados e identidad

Las actualizaciones admitidas son políticas ACL, AppRoles, entidades y grupos internos. Un montaje KV nunca se actualiza, convierte ni desmonta; un cambio de versión o una incompatibilidad produce conflicto.

Las políticas administran su HCL completo, normalizado sintácticamente. Los AppRoles administran las políticas y los límites F06 del blueprint, conservan su RoleID y SecretIDs existentes y no emiten nuevas credenciales. Se preservan `alias_metadata` y los campos no administrados; no se reenvía indiscriminadamente una respuesta GET como cuerpo de actualización.

Las entidades y grupos se actualizan por el UUID registrado, con nombre y tipo comprobados. Se conservan metadata y aliases no administrados. Las políticas, estado disabled y listas de miembros que forman parte de la especificación son campos administrados; las listas se sustituyen según el descriptor validado.

Un grupo propio puede añadir una referencia lógica a una entidad o grupo todavía ausente si su creación figura antes en el DAG. Los UUID se resuelven después de crearlos; la configuración actual del grupo sigue participando en el preflight.

Las referencias lógicas de grupos propios o nuevos deben apuntar a identidades propias verificadas o a creaciones planificadas. Una identidad existente equivalente pero externa produce `unmanaged_reference`: su nombre no basta para conservar una autorización si alguien la reemplaza. Un grupo externo que permanece como noop sigue siendo externo. Los UUID declarados directamente en el descriptor constituyen una selección explícita y continúan admitidos.

La identidad se comprueba mediante UUID para entidades/grupos, accessor para montajes KV y un hash de RoleID más accessor del montaje de autenticación para AppRoles. El RoleID no se guarda en claro. La API de políticas no ofrece un identificador de generación estable: borrar y recrear una política idéntica no es detectable por su fingerprint.

## Inventario, destino y archivos

El estado JSON versionado usa `api_version: secretwright/state/v1`, nombre del blueprint, revisión y registros de recursos. El destino incluye `cluster_id`, namespace y SHA-256 de la dirección configurada normalizada. Cambiar cualquiera de esos valores rechaza la operación antes de escribir en Vault. Se exige un servidor inicializado, desellado y con cluster ID disponible.

Cada registro contiene ID lógico, tipo, nombre, montaje de autenticación cuando corresponda, identidad no secreta o su hash, baseline y estado pendiente. No se guardan valores KV, HCL, especificaciones completas, variables, tokens, RoleID ni SecretID. Los planes e informes públicos no muestran el inventario, sus hashes ni errores arbitrarios de Vault.

El lector exige JSON estricto, UTF-8 válido, claves únicas a cualquier profundidad, tipos y campos conocidos, sin varios documentos, NUL ni contenido sobrante. Se rechazan IDs o locators duplicados, hashes inválidos y combinaciones de campos incompatibles con el tipo de recurso.

Leer un inventario requiere un archivo regular `0600`; no se corrigen permisos automáticamente ni se siguen symlinks finales. `apply` y `recover` crean cooperativamente `STATE.lock` de forma exclusiva, con modo `0600`, antes de leer el inventario. El lock se conserva durante toda la operación y solo se elimina si sigue siendo el archivo creado por ese proceso.

Un lock abandonado por un proceso caído no se roba ni elimina automáticamente. El operador puede retirarlo solo después de comprobar que no hay una operación activa. La protección cooperativa no cubre ediciones maliciosas de otros procesos con el mismo usuario del sistema operativo.

Cada checkpoint valida el nuevo estado antes de escribirlo, incrementa la revisión y comprueba que el archivo no haya cambiado en contenido, identidad o permisos desde su última lectura. La publicación usa un temporal privado hermano, escritura completa, sincronización, rename atómico y sincronización del directorio. Un fallo después de publicar el rename se considera persistencia incierta. Un fallo o una carrera no autoriza a sobrescribir archivos reemplazantes.

## Preflight, escrituras pendientes y recuperación

Antes de la primera mutación o checkpoint se completa la planificación de todos los recursos. Conflictos, denegaciones y lecturas inválidas impiden tanto las escrituras Vault como los checkpoints del plan. Antes de actuar se relee cada recurso, incluidos los noops, y se compara con el preflight. Una creación concurrente se rechaza aunque parezca equivalente.

Cada creación o actualización guarda primero un registro `pending: create` o `pending: update`. Solo después se envía una mutación. Tras verificar el resultado se publica el nuevo baseline y se elimina el pending. Una actualización pendiente conserva su baseline e identidad anteriores. Una creación pendiente no afirma una identidad ni un baseline todavía confirmados.

Un error definitivo permite restaurar el registro anterior o retirar la reserva de creación mediante otro checkpoint. Una respuesta perdida, una verificación posterior fallida o un fallo al guardar el resultado deja una operación pendiente y detiene la ejecución. No hay rollback de recursos ni reintento automático. Cualquier pending impide los plan/apply normales hasta una recuperación explícita.

```bash
# Solo consulta Vault y recupera checkpoints locales: no aplica recursos.
secretwright blueprint recover --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token

# Permiso explícito para reclamar una creación incierta que ahora existe
# y coincide con el descriptor; revisar antes el recurso observado.
secretwright blueprint recover --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --adopt-pending --token-file operator-token
```

La recuperación exige que todos los registros pendientes sigan declarados con el mismo destino y locator. En una actualización pendiente, si el recurso conserva su identidad y coincide con el baseline anterior, se retira el pending como no aplicado; si coincide con el estado deseado, se confirma su baseline actual. Cualquier otro estado produce conflicto.

En una creación pendiente, si el recurso sigue ausente se retira la reserva. Si existe y es equivalente, solo puede reclamarse con `--adopt-pending`; no se afirma automáticamente que fue creado por la operación incierta. Un recurso incompatible, una identidad reemplazada o una referencia irresoluble impide toda la recuperación, sin checkpoint parcial. Si no hay pendientes, recover no incrementa la revisión.

Se completan todas las lecturas necesarias antes de un único checkpoint de recuperación. Recover nunca crea ni actualiza recursos en Vault. Los registros no pendientes conservan su baseline; los omitidos no pendientes siguen retenidos.

## Carreras y resultados

Las APIs administrativas de Vault no ofrecen CAS atómico para estas configuraciones. La relectura y la verificación posterior reducen las carreras, pero otra operación puede intervenir entre la última lectura y la escritura. El lock local protege el inventario cooperativo, no bloquea otros clientes Vault.

Planes e informes contienen metadatos: ID, tipo, nombre, acción/estado, motivo categórico, propiedad local y drift cuando corresponda. No se aceptan como autoridad para ejecutar una operación posterior. La aplicación vuelve a inspeccionar el estado real.

Los códigos son `0` por éxito; `1` por entrada/configuración/salida inválida; `2` por autenticación o permisos; `3` por prerrequisito no encontrado; `4` por conflicto, pending, destino incorrecto, lock o inventario cambiado; `5` por cambios parciales o resultado/persistencia inciertos. La cancelación sin cambios devuelve `130`. Tras una creación o actualización confirmada, un fallo posterior devuelve `5` y conserva lo ya aplicado.

## Opciones y límites

`adopt`, `recover` y los plan/apply con estado aceptan las opciones de conexión F07. El timeout limita la operación completa. `--repair` solo se admite con `--state` en plan/apply; `--adopt-pending` solo en recover. Schema y validate siguen offline y rechazan las opciones de estado.

Los archivos deben tener nombre real: no se admite stdin ni `-`. No hay cwd KV, flags KV ni argumentos posicionales. En la shell se conserva la conexión para las acciones online; los comandos blueprint siguen fuera del historial y del completado de rutas.

| Elemento | Límite |
| --- | --- |
| Blueprint | Límites F07: 128 recursos deseados y 4 MiB expandidos |
| Inventario JSON | 1 MiB |
| Registros de inventario, incluidos retenidos | 256 |
| Profundidad y nodos JSON del inventario | 32 niveles y 10 000 nodos |
| Revisión | 1 a MaxInt64, incremento de uno por checkpoint |

Los límites se comprueban sin truncar registros ni omitir recursos. Se rechaza en preflight una operación cuyo inventario posible superaría el máximo.

## Pruebas de aceptación

El contrato y las pruebas se publican antes de la implementación. F09 conserva la regresión F00–F08 y añade:

- Adopción explícita de equivalentes e inicialización de inventario vacío, sin escrituras Vault ni sobrescritura de archivos existentes.
- Binding de dirección, namespace, cluster y blueprint; mismatches sin mutaciones.
- JSON estricto y archivos privados, lock exclusivo, detección de reemplazos y checkpoints atómicos.
- Drift bloqueado por defecto; reparación explícita de política, AppRole, entidad y grupo; cambios deseados propios e idempotencia posterior.
- Conservación de recursos externos y retenidos, conflicto ante identidad reemplazada o desaparición y ausencia de eliminaciones implícitas.
- Referencias de grupo hacia UUID recién creados y conservación de alias metadata, CIDRs, RoleID, SecretIDs, metadata y aliases no administrados.
- Registro pendiente antes de mutar, parada tras errores inciertos, fallos de persistencia sin nuevas escrituras y recuperación sin mutaciones Vault.
- Permisos efectivos antes y después de reconciliar contra Vault real, CLI/shell y ausencia de secretos en estado, informes y diagnósticos.
