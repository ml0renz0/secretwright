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

El flujo exige un tag SemVer que apunte a un commit del historial de `main`, ejecuta la CI completa y publica únicamente después de verificar el bundle y su firma. No sobrescribe releases existentes. Si una publicación se interrumpe, inspecciona el borrador y sus assets antes de decidir cómo continuar.

Consulta el [contrato F13](features/F13-packaging-release.md) para los artefactos, controles y límites exactos.
