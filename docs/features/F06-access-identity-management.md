# F06 — Accesos e identidades

## Objetivo

Administrar políticas ACL, AppRoles, entidades y grupos internos; consultar permisos del token actual y emitir o revocar credenciales. Los comandos utilizan la conexión, TLS, namespaces y selección explícita de token existentes. Esta fase prepara los recursos que podrán utilizar los blueprints posteriores.

El producto no habilita métodos de autenticación ni instala políticas automáticamente. AppRole utiliza un montaje de autenticación ya existente, `approle` por defecto o el indicado con `--auth-mount`. No se implementan alias, grupos externos, renovación, rotación ni reconciliación declarativa en F06.

## Comandos y configuración

```text
policy list
policy read NAME
policy write --file POLICY.hcl NAME
policy delete --force NAME

approle list
approle read NAME
approle write --file ROLE.json NAME
approle delete --force NAME
approle role-id --out FILE NAME
approle credentials --out FILE NAME
approle revoke-secret-id --file CREDENTIALS.json NAME
approle login --file CREDENTIALS.json --out TOKENFILE

token create --file SPEC.json --out TOKENFILE
token revoke --force --file TARGETTOKENFILE
token revoke-self --force
token capabilities API_PATH...

identity entity list
identity entity read ID
identity entity write --file SPEC.json [ID]
identity entity delete --force ID
identity group list
identity group read ID
identity group write --file SPEC.json [ID]
identity group delete --force ID
```

Se antepone `secretwright` a cada línea. Las opciones van después de la acción más específica y antes de los argumentos posicionales: por ejemplo, `secretwright identity entity read --token-file admin-token ID`.

Se admiten `--address`, `--namespace` y `--timeout`. Las operaciones autenticadas admiten `--token-file`; AppRole admite además `--auth-mount`. No se usa el directorio KV ni las opciones `--cwd`, `--mount` o `--kv-version`. Login AppRole no acepta `--token-file`: se autentica únicamente con las credenciales de su archivo y no envía `VAULT_TOKEN` ni el token del operador.

Todos los archivos requieren nombres reales mediante `--file` o `--out`; no se admite `-` ni se consume stdin. La ayuda funciona sin credenciales ni red. Los archivos de configuración se validan completamente antes de cargar credenciales o contactar con Vault.

## Políticas ACL y permisos

Las políticas utilizan la API moderna `sys/policies/acl`. `list` devuelve nombres ordenados y `read` devuelve el nombre y el HCL solicitado. `write` recibe HCL UTF-8 no vacío, de hasta 1 MiB; Vault valida su sintaxis y sus reglas. No se reproducen cuerpos de error del servidor.

Se rechaza modificar o borrar la política `root`, y borrar `default`. La actualización de `default` sigue siendo una operación administrativa explícita. La eliminación requiere `--force`.

`token capabilities` consulta exclusivamente las capacidades del token seleccionado, mediante `sys/capabilities-self`. Recibe entre 1 y 100 rutas físicas de la API de Vault, sin `/v1/` inicial. Por ejemplo:

```bash
secretwright token capabilities --token-file app-token \
  secret/data/app/database secret/metadata/app/
```

No convierte rutas KV lógicas en rutas API. Devuelve rutas y listas ordenadas de capacidades conocidas; no consulta secretos ni acredita permisos sobre otros recursos.

## AppRoles

La configuración JSON de un rol admite los siguientes campos:

```json
{
  "token_policies": ["app-read"],
  "token_ttl": "5m",
  "token_max_ttl": "1h",
  "secret_id_ttl": "10m",
  "secret_id_num_uses": 1,
  "token_num_uses": 0
}
```

Las políticas son explícitas, no vacías y no pueden incluir `root`. Las tres duraciones son obligatorias, positivas, expresadas en segundos completos mediante unidades de Go, y no superan 24 horas; el TTL máximo del token debe cubrir su TTL inicial. SecretID admite entre 1 y 1000 usos. `token_num_uses` es opcional y vale `0` por defecto, sin límite de usos durante su vigencia; admite hasta 1000.

La escritura fija `bind_secret_id=true`, `token_no_default_policy=true` y tokens de tipo `service`, y limpia cualquier período de token previo. No permite introducir IDs de token, periodos, credenciales huérfanas, metadatos ni campos arbitrarios. `read` proyecta únicamente la configuración permitida y puede mostrar la configuración real de roles externos a Secretwright; no revela RoleID ni SecretID.

`approle role-id` exporta el RoleID a un archivo privado, incluso cuando solo se consulta. Un RoleID puede ser suficiente para autenticar si otro administrador ha desactivado la exigencia de SecretID.

`approle credentials` comprueba que el rol exija SecretID, políticas explícitas, tiempos/usos acotados y tokens de servicio sin período. La respuesta debe confirmar el tipo y el período; no se asumen valores seguros si faltan. Después lee el RoleID y genera un SecretID. Exporta exclusivamente un archivo JSON con `role_id`, `secret_id` y `secret_id_accessor`. La comprobación no bloquea cambios concurrentes del rol; las APIs administrativas de Vault no ofrecen CAS.

```bash
secretwright approle write --token-file admin-token --file role.json app
secretwright approle credentials --token-file admin-token --out app-credentials.json app
secretwright approle login --file app-credentials.json --out app-token
secretwright cat --token-file app-token /secret/app/database
```

Login recibe las credenciales del archivo, sin sustituir el token de la shell, el entorno ni ningún archivo previo. El token resultante se guarda como texto compatible con `--token-file`. La salida normal contiene solamente metadatos aprobados: políticas, vigencia, renovación e identificador de entidad cuando lo devuelve Vault.

`approle revoke-secret-id` usa el accessor guardado en el archivo y el nombre del rol elegido explícitamente. Destruir un SecretID o borrar un rol impide autenticaciones futuras, pero no revoca los tokens ya emitidos; estos deben revocarse por separado.

## Emisión y revocación de tokens

El archivo de `token create` contiene políticas explícitas y tiempos finitos:

```json
{
  "policies": ["app-read"],
  "ttl": "5m",
  "explicit_max_ttl": "1h",
  "renewable": false,
  "num_uses": 0
}
```

Las políticas son obligatorias, no vacías y excluyen `root`: no se permite heredar implícitamente la lista de políticas del token emisor. Ambos tiempos son obligatorios y positivos, hasta 24 horas, con máximo no inferior al TTL. Se crean tokens `service`, hijos del emisor y sin la política `default` añadida automáticamente. No se admiten IDs elegidos por el usuario, tokens huérfanos, periodos, roles de emisión ni metadatos arbitrarios.

Vault conserva la identidad del padre en los tokens hijos. Si el emisor pertenece a una entidad o grupo con políticas, esos permisos derivados de identidad pueden estar presentes también en el hijo, aunque su lista de políticas de token sea explícita. El informe incluye `entity_id` cuando existe. La creación de tokens hijos no proporciona aislamiento respecto a los permisos de identidad del emisor; se conserva esta semántica de Vault y se comprueba con un caso de integración.

Las políticas declaradas deben conceder las operaciones de autoinspección o autorrevocación que se necesiten. Un token puede servir para leer secretos y recibir `403` en `auth check`, como ya establece F01.

`token revoke` lee el token objetivo desde un archivo y utiliza el token administrativo seleccionado para revocarlo con sus descendientes. `token revoke-self` revoca el token actual y sus descendientes. Ambos requieren `--force`; no aceptan tokens o accessors como argumentos.

## Entidades y grupos internos

Las entidades admiten `name`, `policies` y `disabled`. Los grupos internos admiten `name`, `policies`, `member_entity_ids` y `member_group_ids`. El nombre es obligatorio; las políticas y los miembros pueden ser arrays vacíos. Los IDs son UUID y los miembros se limitan a 1000 por lista.

Sin ID, `write` utiliza la creación por nombre de Vault, que puede actualizar un recurso existente con ese nombre. Con ID, verifica el recurso y lo actualiza explícitamente. Las escrituras establecen toda la configuración admitida: omitir `policies` o una lista de miembros la vacía; omitir `disabled` establece `false`. Las listas de miembros representan la lista completa configurada. No se convierten grupos externos en internos de manera implícita.

Los resultados se limitan a IDs, nombres, políticas, estado y miembros permitidos. Se excluyen metadatos, alias y campos arbitrarios del servidor. El `entity_id` devuelto por un login permite asociar la entidad creada por AppRole a un grupo interno con políticas adicionales.

Las escrituras administrativas no son transacciones ni tienen CAS: una escritura concurrente posterior puede prevalecer. Borrar una entidad o cambiar sus políticas no equivale a revocar explícitamente sus tokens.

## Archivos de credenciales y fallos

Los archivos de salida se reservan exclusivamente con permisos `0600` antes de emitir credenciales. Si ya existe un archivo o enlace, la operación falla sin contactar con Vault. Durante la operación el archivo reservado puede estar vacío; se considera completado cuando la escritura, sincronización y cierre terminan correctamente. Los fallos eliminan el archivo reservado por la operación.

RoleID, SecretID, tokens y accessors no aparecen en stdout, stderr, historial ni informes JSON. Los tipos de respuesta que contienen secretos tampoco los exponen mediante serialización JSON genérica; el bundle de AppRole tiene un codificador privado explícito.

Si se conoce una credencial recién emitida y falla su archivo, se intenta una revocación compensatoria con un plazo máximo de cinco segundos, independiente de la cancelación original. Un token creado se revoca por accessor con el emisor; un token de login intenta autorrevocarse; un SecretID se destruye por accessor. La compensación depende de los permisos disponibles y no constituye una transacción.

Una compensación confirmada devuelve error `1` y elimina el archivo. Si no puede confirmarse, o se pierde o recibe una respuesta inválida durante la emisión, se devuelve `5` con un mensaje estático que exige comprobar el estado antes de reintentar. Nunca se vuelven a emitir credenciales automáticamente ni se imprimen para recuperarlas. Un fallo al escribir el informe de stdout después de guardar correctamente el archivo no revoca la credencial ni borra ese archivo.

## Límites y códigos

Los archivos JSON de configuración y credenciales se limitan a 64 KiB. Se rechazan campos desconocidos, miembros duplicados, tipos incorrectos y documentos adicionales. Los nombres son ASCII alfanuméricos con `.`, `_` y `-`, hasta 128 caracteres. Los montajes de autenticación utilizan segmentos de ese tipo; no admiten rutas URL ni `.`/`..`. Las listas devueltas por Vault se limitan a 10 000 elementos, sin truncado silencioso.

Se conserva el namespace y el plazo completo de cada operación. No hay reintentos, redirecciones, wrapping heredado ni autoinspección obligatoria del token administrativo.

| Código | Resultado |
| --- | --- |
| `0` | Operación y salida completadas. |
| `1` | Opciones, archivos, configuración, respuesta o salida inválidos; compensación confirmada tras fallo de archivo. |
| `2` | Falta autenticación o Vault deniega la operación. |
| `3` | Recurso no encontrado. |
| `5` | Mutación/emisión incierta o fallo de archivo con revocación sin confirmar. |
| `130` | Cancelación sin mutación incierta. |

## Shell y pruebas de aceptación

Los comandos administrativos conservan la conexión y el token fijados al iniciar la shell, sin recibir cwd. Login conserva la conexión y el namespace pero omite el token del operador. La detección de overrides respeta las acciones anidadas, también después de flags booleanos; no se puede cambiar la conexión mediante `identity entity write --address ...`.

Todos los comandos F06 quedan fuera del historial aprobado. Tab añade solamente sus nombres superiores; no completa credenciales, archivos, IDs, nombres de políticas o rutas administrativas remotas.

El contrato y las pruebas preceden a la implementación. Además de formato, vet, pruebas con `-race`, compilación estática y regresión F00–F05, la fase debe demostrar:

- Políticas y AppRoles contra Vault real, con acceso concedido a un secreto y denegado a otro.
- Token de creación con políticas explícitas, sin heredar la lista de políticas del token administrativo; conservación documentada de la identidad del padre y de sus permisos de grupo.
- Login sin el token del operador; SecretID revocado que impide otro login mientras el token ya emitido sigue funcionando; revocación posterior de ese token.
- Entidad de login asociada a un grupo interno que concede la política esperada.
- Validación íntegra antes de red, archivos exclusivos `0600`, conservación de archivos/enlaces existentes y compensación de fallos de escritura.
- Respuestas perdidas o inválidas sin reintentos ni filtración de credenciales en resultados, errores, logs o historial.
