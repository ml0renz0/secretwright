# F12 — Kerberos y keytabs

## Alcance

Leer keytabs MIT v2 con Go, inspeccionar sus principales, KVNO y tipos de cifrado, validar una política explícita y guardar o recuperar el binario completo mediante Vault KV v2. No se necesita `klist` ni un runtime Kerberos.

La validación comprueba estructura y política, no autenticación contra un KDC, contraseña, entropía de las claves o estado de la cuenta. Todos los informes declaran `authentication_checked: false`. El timestamp de una entrada es un dato de creación; no representa caducidad.

Esta entrega no genera ni rota claves Kerberos y no obtiene tickets. Los keytabs v1 se rechazan: su orden de bytes depende de la máquina que los produjo y no se adivina.

## Inspección y política

```bash
secretwright keytab inspect --file service.keytab
secretwright keytab validate --file service.keytab
secretwright keytab example > policy.yaml
secretwright keytab example --format json > policy.json
secretwright keytab schema
secretwright keytab validate --file service.keytab --policy policy.yaml
```

Inspect muestra solo metadatos: principal, realm, componentes, tipo de nombre, timestamp UTC, KVNO efectivo, enctype, clasificación y longitud de clave. Nunca muestra claves, base64 ni hashes del keytab o de sus claves.

Validate sin política comprueba el formato y rechaza entradas duplicadas ambiguas; devuelve `policy_checked: false`. Un archivo v2 vacío puede ser estructuralmente válido. Para exigir una identidad y unas claves concretas se proporciona una política:

```yaml
api_version: secretwright/keytab/v1
name: web
principal:
  realm: EXAMPLE.TEST
  components: [HTTP, app.example.test]
minimum_kvno: 3
allowed_enctypes: [17, 18, 19, 20]
required_enctypes: [18]
allow_other_principals: false
```

La identidad se expresa mediante campos estructurados, respetando mayúsculas y componentes exactos. Así se distingue un componente que contiene `/` de dos componentes separados. Su presentación textual escapa `/`, `@` y `\`; esa presentación no se divide ingenuamente para comprobar una política.

La política exige que exista el principal, que todas sus entradas tengan al menos el KVNO mínimo y que sus tipos estén permitidos. Los tipos requeridos deben existir en el **KVNO más alto**: una clave antigua no satisface el requisito de la versión actual. Los principales adicionales se rechazan salvo autorización explícita. Si se permiten, sus bytes también se guardan; no se filtra el archivo.

El ejemplo permite AES 128/256 con SHA-1 o SHA-2 y exige AES256-SHA1. También se reconocen DES, 3DES, RC4 y Camellia con sus longitudes correspondientes. Los tipos legacy pueden admitirse mediante una elección explícita de política; su clasificación sigue siendo visible. Los tipos desconocidos se pueden inspeccionar, pero no se admiten en una política que el producto no sabe validar.

Los documentos YAML/JSON son estrictos: campos desconocidos, duplicados, aliases, varios documentos y tipos ambiguos se rechazan. No hay includes ni expansión de variables. El esquema Draft 2020-12 publicado y embebido es `schemas/keytab-v1.schema.json`, ID `urn:secretwright:keytab:v1`; no carga referencias externas. Las políticas generadas usan YAML por defecto, con JSON opcional.

## Guardar y recuperar en Vault

```bash
# Crear una ruta nueva; CAS 0 es el comportamiento predeterminado.
secretwright keytab import --file service.keytab --policy policy.yaml \
  --mount secret --path /secret/kerberos/web --token-file operator-token

# Sustituir solo si la revisión actual sigue siendo la 1.
secretwright keytab import --file updated.keytab --policy policy.yaml \
  --mount secret --path /secret/kerberos/web --cas 1 --token-file operator-token

# Exportar la revisión actual hacia un archivo nuevo privado.
secretwright keytab export --mount secret --path /secret/kerberos/web \
  --out restored.keytab --policy policy.yaml --token-file operator-token

# Seleccionar una revisión histórica exacta.
secretwright keytab export --mount secret --path /secret/kerberos/web \
  --version 1 --out previous.keytab --token-file operator-token
```

El montaje KV v2 debe existir y se selecciona explícitamente. La ruta es absoluta, canónica y está debajo de ese montaje. No hay descubrimiento automático, KV v1 ni uso de `cwd`. CAS protege la escritura y no sustituye una revisión concurrente; una ruta con historial no se convierte en nueva por haber borrado su versión actual.

El valor en KV contiene exactamente `api_version`, `encoding: base64` y `data` con el binario codificado. **Base64 no es cifrado**: los permisos de Vault y los archivos privados protegen el material. La lectura rechaza campos extra, codificación no canónica y binarios inválidos antes de publicar una salida.

La exportación conserva los bytes originales, incluidos huecos y padding; no limpia restos ni regenera entradas. El informe devuelve la revisión de la misma respuesta leída. Una versión borrada, destruida o ausente no provoca fallback a otra.

## Formato y límites

El lector admite cabecera `05 02`, enteros big-endian, registros activos, huecos negativos y terminador cero. Un registro puede superar el tamaño de la entrada por reutilizar un hueco; ese padding se conserva. KVNO32 no cero sustituye a KVNO8; cero o ausencia conserva KVNO8. Los timestamps son enteros sin signo y se interpretan también después de 2038.

Se limita el archivo a 1 MiB y 4096 registros, con hasta 32 componentes por principal y cadenas de hasta 1024 bytes; la presentación completa del principal tiene un máximo de 4096. Los textos son UTF-8 sin controles. Se rechazan truncados, longitudes inconsistentes, claves vacías, longitudes incorrectas de cifrados conocidos y datos reales después del terminador. Los huecos son opacos, no entradas activas.

Duplicados con el mismo principal, KVNO y enctype se pueden inspeccionar, pero fallan la validación aunque tengan otro `name_type`. No se compara ni se calcula un hash de los valores secretos para decidirlo.

## Archivos, errores y shell

Los keytabs locales requieren archivos regulares `0600`, sin symlinks finales ni bits especiales. Las políticas pueden ser públicas, pero también deben ser archivos regulares acotados. No se acepta `-`, stdin ni valores de clave en argv. La lectura comprueba inodo, modo y tamaño antes y después de leer y validar.

Los inputs, la política, la ruta Vault y la reserva exclusiva de la salida se validan antes de seleccionar el operador o iniciar HTTP. Export nunca sobrescribe un archivo o enlace existente. Si falla stdout después de guardar un archivo, el archivo se conserva.

Import sin respuesta confirmada devuelve `5`, sin retry, rollback ni compensación. También devuelve `5` si la escritura se confirmó y después falló el informe. Export es una lectura; si su informe falla tras guardar, devuelve error de salida y conserva el archivo. Las respuestas de lectura KV están acotadas antes de decodificar el contenido.

La conexión y timeout existentes se aplican a la operación online completa. La shell conserva su conexión fija, mantiene los comandos offline sin credenciales y excluye todo `keytab` del historial. El autocompletado solo ofrece el grupo, sin enumerar rutas ni principales.

Códigos: `0` éxito; `1` entrada/configuración/archivo; `2` autenticación o permisos; `3` ausente; `4` política, duplicados, conflicto CAS o salida existente; `5` import parcial o incierto; `130` cancelación previa a efectos. Los diagnósticos son fijos y las escrituras cortas de stdout se detectan.

## Aceptación

Contrato y pruebas publicados antes de implementar. Se exige:

- Fixtures binarias nativas, v2, huecos, padding, terminador, KVNO8/32, timestamps posteriores a 2038 y principales escapados sin colisiones.
- Rechazo de truncados, v1, longitudes extremas, claves vacías y longitudes incorrectas; inspección de tipos legacy y desconocidos sin revelar claves.
- Políticas con identidad exacta, duplicados, KVNO mínimo y tipos requeridos en la versión más alta; YAML/JSON y esquemas estrictos.
- Vault real: roundtrip byte a byte, CAS y concurrencia, revisión histórica exacta, ausencia de fallback, permisos efectivos y respuesta perdida con una sola escritura.
- Archivos privados, enlaces y salidas existentes, preflight antes de HTTP, shell e informes sin secretos.
- Fuzzing acotado y regresión F00–F11, incluidos PostgreSQL y PKI/TLS/CRL reales. No se afirma haber autenticado con un KDC.
