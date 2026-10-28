# Instalar y verificar Secretwright

El repositorio y sus releases pueden ser privados. Los ejemplos con `gh` requieren una sesión con acceso al repositorio. Sustituye `VERSION` por una versión publicada; los snapshots de Actions son artefactos temporales de CI.

## Binario

Cada release ofrece Linux, macOS y Windows para amd64 y arm64. Descarga el paquete correspondiente y su manifiesto firmado:

```bash
VERSION=1.0.0
gh release download "v$VERSION" --repo ml0renz0/secretwright \
  --pattern "secretwright_${VERSION}_linux_amd64.tar.gz" \
  --pattern "secretwright_${VERSION}_checksums.txt" \
  --pattern "secretwright_${VERSION}_checksums.sig" \
  --pattern "secretwright_${VERSION}_signing-key.pem"
```

Primero selecciona una clave pública cuyo origen o huella hayas verificado por un canal independiente. La clave incluida permite identificar al firmante, pero su descarga por sí sola no establece confianza. Con OpenSSL 3 y la clave confiable guardada como `trusted-release-key.pem`:

```bash
openssl pkeyutl -verify -pubin -rawin \
  -inkey trusted-release-key.pem \
  -in "secretwright_${VERSION}_checksums.txt" \
  -sigfile "secretwright_${VERSION}_checksums.sig"

# Comprueba los assets descargados del manifiesto ya autenticado.
sha256sum --check --ignore-missing "secretwright_${VERSION}_checksums.txt"

tar -xzf "secretwright_${VERSION}_linux_amd64.tar.gz"
./secretwright version
./secretwright help
```

En macOS usa la herramienta SHA-256 equivalente disponible; para Windows extrae el ZIP y ejecuta `secretwright.exe`. Las funciones que exigen permisos POSIX privados siguen siendo experimentales en Windows: el paquete no acredita soporte de ACL Windows.

El binario no requiere un runtime Go ni Kerberos. La conexión HTTPS usa las CA del sistema y permite configurar una CA privada mediante `VAULT_CACERT`. Los ejemplos de configuración generados usan YAML por defecto y admiten JSON explícito.

## Contenedor Linux

La release incluye un archivo OCI con amd64 y arm64. Tras verificar su firma y checksum, una herramienta compatible con OCI puede importar la arquitectura del host al daemon Docker; por ejemplo, con Skopeo:

```bash
skopeo copy --override-os linux --override-arch amd64 \
  "oci-archive:secretwright_${VERSION}_linux_multiarch.oci.tar" \
  "docker-daemon:secretwright:verified"

docker run --rm --read-only --network none secretwright:verified version
docker run --rm --read-only --network none secretwright:verified keytab example
```

La imagen se ejecuta por defecto como UID/GID `65532:65532`. Para leer archivos privados del host, usa su propietario y un montaje explícito. Este ejemplo Unix inspecciona un keytab `0600` sin red:

```bash
docker run --rm --read-only --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/private,dst=/private,readonly" \
  secretwright:verified keytab inspect --file /private/service.keytab
```

Para operaciones online añade los parámetros de Vault y los montajes del token y las CA necesarias. Los archivos de salida requieren un directorio montado con escritura y propiedad compatible. Mantén `0600`; no conviertas el archivo en público para facilitar el montaje.

La imagen no incluye shell ni gestor de paquetes. Los comandos de Secretwright se pasan directamente tras el nombre de la imagen.

## Preparar una release

Los mantenedores configuran una clave de firma estable y su contraseña como secretos de Actions. La clave no se incorpora a Git. Puede generarse una clave Ed25519 PKCS#8 cifrada con OpenSSL, conservándola en un almacén privado; su clave pública y huella se distribuyen por un canal confiable.

### Configurar la primera clave

Ejecuta este bloque con Bash, Git, OpenSSL 3 y una sesión de `gh` con permisos para administrar los secretos del repositorio, desde tu propio equipo. Consulta solo los nombres de los secretos existentes y se detiene si ya hay configuración de firma, para conservar la identidad del firmante.

La clave cifrada queda en un directorio nuevo privado fuera del checkout. La ruta propuesta está en tu home; `SECRETWRIGHT_SIGNING_DIRECTORY` permite seleccionar otra ruta absoluta cuyo directorio padre ya exista. El bloque rechaza un padre dentro de un checkout Git. Conserva ese directorio y la contraseña en tu almacén privado. Solo se muestra la huella pública; no copies la clave ni la contraseña al chat.

```bash
(
  set +x
  set -euo pipefail
  umask 077
  export GH_HOST=github.com
  secretwright_repo=ml0renz0/secretwright
  gh auth status --hostname github.com >/dev/null 2>&1
  secretwright_existing=$(gh secret list --repo "$secretwright_repo" --app actions \
    --json name --jq '[.[] | select(.name == "SECRETWRIGHT_SIGNING_KEY" or .name == "SECRETWRIGHT_SIGNING_PASSWORD")] | length')
  if [[ "$secretwright_existing" != 0 ]]; then
    printf '%s\n' 'Ya existe configuración de firma; conserva la clave actual y revisa ambos nombres.' >&2
    exit 1
  fi
  secretwright_signing_dir="${SECRETWRIGHT_SIGNING_DIRECTORY:-$HOME/secretwright-release-signing}"
  if [[ "$secretwright_signing_dir" != /* || -e "$secretwright_signing_dir" || -L "$secretwright_signing_dir" ]] || \
     git -C "$(dirname -- "$secretwright_signing_dir")" rev-parse --show-toplevel >/dev/null 2>&1; then
    printf '%s\n' 'Selecciona un directorio nuevo absoluto fuera de un checkout Git.' >&2
    exit 1
  fi
  IFS= read -r -s -p 'Contraseña de la nueva clave: ' SECRETWRIGHT_SIGNING_PASSWORD
  printf '\n'
  IFS= read -r -s -p 'Repite la contraseña: ' secretwright_confirmation
  printf '\n'
  if [[ -z "$SECRETWRIGHT_SIGNING_PASSWORD" || "$SECRETWRIGHT_SIGNING_PASSWORD" != "$secretwright_confirmation" ]]; then
    printf '%s\n' 'Las contraseñas deben coincidir y no estar vacías.' >&2
    exit 1
  fi
  mkdir -m 0700 -- "$secretwright_signing_dir"
  export SECRETWRIGHT_SIGNING_PASSWORD
  openssl genpkey -algorithm ED25519 -aes-256-cbc \
    -pass env:SECRETWRIGHT_SIGNING_PASSWORD -out "$secretwright_signing_dir/release-signing-key.pem"
  openssl pkey -in "$secretwright_signing_dir/release-signing-key.pem" \
    -passin env:SECRETWRIGHT_SIGNING_PASSWORD -pubout -out "$secretwright_signing_dir/trusted-release-key.pem"
  gh secret set SECRETWRIGHT_SIGNING_KEY --repo "$secretwright_repo" --app actions \
    < "$secretwright_signing_dir/release-signing-key.pem"
  printf '%s' "$SECRETWRIGHT_SIGNING_PASSWORD" | \
    gh secret set SECRETWRIGHT_SIGNING_PASSWORD --repo "$secretwright_repo" --app actions
  unset SECRETWRIGHT_SIGNING_PASSWORD secretwright_confirmation
  printf '%s\n' 'Huella SHA-256 de la clave pública (formato DER):'
  openssl pkey -pubin -in "$secretwright_signing_dir/trusted-release-key.pem" -outform DER | openssl dgst -sha256
  printf 'Conserva la clave cifrada y la clave pública en: %s\n' "$secretwright_signing_dir"
)
```

Si falla la carga de uno de los secretos, conserva los archivos de esa misma clave. Los valores configurados no se pueden recuperar leyendo los secretos de Actions. Este bloque recarga los dos valores desde la clave que acabas de guardar, comprueba antes su contraseña y muestra su huella para contrastarla con la registrada. Úsalo solo para completar esa misma configuración, manteniendo el mismo directorio:

```bash
(
  set +x
  set -euo pipefail
  umask 077
  export GH_HOST=github.com
  secretwright_signing_dir="${SECRETWRIGHT_SIGNING_DIRECTORY:-$HOME/secretwright-release-signing}"
  test -f "$secretwright_signing_dir/release-signing-key.pem"
  test ! -L "$secretwright_signing_dir/release-signing-key.pem"
  IFS= read -r -s -p 'Contraseña de la clave conservada: ' SECRETWRIGHT_SIGNING_PASSWORD
  printf '\n'
  export SECRETWRIGHT_SIGNING_PASSWORD
  openssl pkey -in "$secretwright_signing_dir/release-signing-key.pem" \
    -passin env:SECRETWRIGHT_SIGNING_PASSWORD -pubout -outform DER | openssl dgst -sha256
  gh secret set SECRETWRIGHT_SIGNING_KEY --repo ml0renz0/secretwright --app actions \
    < "$secretwright_signing_dir/release-signing-key.pem"
  printf '%s' "$SECRETWRIGHT_SIGNING_PASSWORD" | \
    gh secret set SECRETWRIGHT_SIGNING_PASSWORD --repo ml0renz0/secretwright --app actions
)
```

### Publicar candidatas al integrar cambios

El flujo normal parte de `.github/release.yaml`:

```yaml
next_version: 0.1.0
promote_candidate: null
```

Configura ambos secretos antes de integrar la preparación en `main`. Cada merge que mantiene la promoción sin cambios activa `Release`: selecciona el commit integrado, ejecuta la CI completa y genera `v0.1.0-rc.N`. `N` es `GITHUB_RUN_NUMBER` del workflow, por lo que puede haber saltos y la primera publicación no tiene por qué terminar en `rc.1`.

El mismo flujo valida el bundle, comprueba la clave de firma fuera de línea y crea el tag y la release. La candidata aparece como prerelease y no se marca como latest. Comprueba los dieciocho assets y la firma con la clave pública conservada.

El workflow se activa con pushes a `main`; subir un tag manual no inicia una publicación. El coordinador ejecuta la CI y la publicación directamente y crea el tag al finalizar las comprobaciones. Así no depende de encadenar otro workflow desde un tag creado con `GITHUB_TOKEN`.

### Liberar la estable mediante una PR

Tras aceptar una candidata publicada, por ejemplo `v0.1.0-rc.4`, abre una PR que solo cambie `.github/release.yaml`:

```yaml
next_version: 0.1.1
promote_candidate: v0.1.0-rc.4
```

El merge aprueba la promoción. CI/CD resuelve el commit de esa RC, comprueba que pertenece al historial de `main` y ejecuta de nuevo la suite completa sobre ese commit. Compila con la versión final `0.1.0`, firma los artefactos, crea `v0.1.0` y publica la estable. GitHub determina si pasa a ser latest mediante su política de fecha de creación y versión SemVer. Los cambios que hayan entrado después en `main` no se añaden a esa estable.

La versión está incorporada al ejecutable: la estable usa el mismo código fuente que la RC seleccionada, pero sus artefactos se recompilan y tienen bytes y hashes distintos. No se renombran los paquetes de la candidata.

Mantén `promote_candidate` sin cambios durante el desarrollo siguiente. Los merges posteriores producirán `v0.1.1-rc.N`. Para corregir una candidata, integra una PR normal en `main`, prueba la nueva RC y selecciona esa RC en la promoción. No se necesita una rama de release permanente.

El fichero admite el subconjunto YAML documentado en el [contrato de releases](features/TBD-releases.md). La próxima versión no puede retroceder; al promover debe avanzar más allá de la estable seleccionada. Una PR de promoción contiene únicamente ese cambio de metadatos.

### Si falla una publicación

La ausencia de los secretos o una clave inválida detienen la publicación antes de crear el tag remoto o la release. Tras completar la configuración, puedes volver a ejecutar el mismo run fallido para conservar su número de RC.

El flujo no sobrescribe tags ni releases existentes. Una interrupción después de crear el tag o el borrador requiere inspeccionar el estado remoto y sus assets antes de continuar; no hay borrado, rollback ni reintento automático que los sustituya. Una RC válida sigue disponible aunque falle su promoción.

Consulta el [contrato F13](features/F13-packaging-release.md) para los artefactos y sus límites, y el [contrato de releases TBD](features/TBD-releases.md) para la planificación y promoción.
