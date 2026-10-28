# Playground de Secretwright

Este laboratorio arranca Vault 2.2.0 en modo dev con contenido ficticio. Permite probar Secretwright con blueprints, secretos KV v1/v2, historial y accesos AppRole. Requiere un Docker local accesible, Python 3 y el binario de Secretwright.

Desde la raíz del repositorio, compila y arranca:

```bash
make playground
source .playground/env.sh
secretwright tree /playground
secretwright shell
```

La compilación requiere Go y `make`. Si ya tienes Secretwright instalado o compilado en `bin/secretwright`, arranca directamente sin Go:

```bash
python3 scripts/playground.py up
source .playground/env.sh
secretwright tree /playground
```

La primera ejecución descarga la imagen de Vault si no está disponible. El laboratorio usa HTTP en `127.0.0.1` con un puerto efímero y conserva las credenciales en archivos privados dentro de `.playground/`, excluido de Git. Todos los valores precargados son ficticios y no corresponden a servicios reales.

`env.sh` exporta `VAULT_ADDR`, `VAULT_NAMESPACE` y `VAULT_TOKEN`, que Secretwright interpreta directamente. El token se lee de su archivo privado al cargar el entorno; no aparece escrito dentro de `env.sh`. También configura el `PATH` del binario seleccionado y el acceso directo a loopback, y despeja las opciones Vault heredadas de agente, TLS y timeout. El directorio tiene permisos `0700` y el archivo de entorno `0600`. En una shell POSIX puedes cargarlo con `. .playground/env.sh`.

## Qué se provisiona

El [blueprint YAML](blueprint.yaml) declara dos montajes, una política ACL y un AppRole. El arranque habilita primero el método de autenticación AppRole, que el motor de blueprints actual requiere existente; después ejecuta `blueprint adopt` y `blueprint apply`, conservando el inventario en `.playground/blueprint.state.json`.

Los archivos de [secrets/](secrets/) aportan los valores mediante `secretwright put`. El blueprint administra la estructura y los accesos; los valores KV se escriben por separado con los comandos de Secretwright. Estos archivos usan JSON porque es el formato de entrada de `put`.

| Recurso | Contenido |
| --- | --- |
| `/playground/apps/payments/database` | Credenciales de base de datos ficticias, con dos versiones. |
| `/playground/apps/payments/config` | Configuración de la aplicación. |
| `/playground/apps/catalog/api` | URL y clave de API ficticia. |
| `/legacy/demo` | Un secreto en KV v1. |
| `playground-read` y `playground-reader` | Política y AppRole de lectura para las aplicaciones de KV v2. |

Puedes ejecutar una comprobación guiada opcional:

```bash
make playground-demo
```

La demo comprueba conexión, autenticación, lectura de valores y versiones, y que el blueprint ya aplicado devuelve un plan vacío. También emite una credencial AppRole, inicia sesión y comprueba tanto una lectura permitida como una escritura denegada. Las credenciales de la demo se guardan en archivos privados; no se imprimen tokens ni SecretIDs.

## Explorar y experimentar

Carga el entorno una vez en tu terminal y ejecuta Secretwright directamente:

```bash
source .playground/env.sh
secretwright status
secretwright mounts
secretwright tree /playground
secretwright cat /playground/apps/payments/database
secretwright versions /playground/apps/payments/database
secretwright cat /legacy/demo
secretwright blueprint plan \
  --file examples/playground/blueprint.yaml --state .playground/blueprint.state.json
```

Abre la shell para navegar, usar Tab o escribir otros comandos:

```bash
secretwright shell
```

Por ejemplo, dentro de la shell:

```text
cd /playground/apps/payments
ls
cat config
versions database
exit
```

Puedes editar una copia de los archivos de ejemplo y escribir nuevas versiones con `secretwright put --file ARCHIVO.json RUTA`. Los cambios se mantienen mientras exista el contenedor. Repetir `up` conserva el laboratorio existente y no vuelve a cargar los valores iniciales. Python se utiliza para preparar, comprobar y retirar el laboratorio; los comandos habituales usan el binario Secretwright.

## Borrar y empezar de nuevo

```bash
make playground-down
unset VAULT_ADDR VAULT_NAMESPACE VAULT_TOKEN
make playground
source .playground/env.sh
```

`down` retira el contenedor que pertenece a este laboratorio y sus archivos locales privados. Vault no usa un volumen persistente: al borrar el contenedor desaparecen sus datos. El siguiente arranque crea de nuevo el contenido inicial y debes volver a cargar `env.sh`, porque la dirección y el token cambian. El comando `unset` limpia esas variables del terminal; no restaura una configuración anterior de Vault.
