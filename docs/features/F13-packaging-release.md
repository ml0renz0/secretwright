# F13 — Empaquetado, releases y distribución

## Alcance

Distribuir Secretwright como binario Go autocontenido, paquetes Debian y una imagen Linux mínima. Cada cambio verifica los paquetes reales antes de preparar una release: compilar no basta para acreditar que el archivo descargable contiene el ejecutable correcto.

Se generan seis archivos comprimidos para Linux, macOS y Windows, en `amd64` y `arm64`: `.tar.gz` para Unix y `.zip` para Windows. Cada uno contiene únicamente el ejecutable, `README.md` y `LICENSE`. Se añaden dos paquetes `.deb`, para Debian amd64 y arm64. La versión se incorpora al binario; los builds usan `CGO_ENABLED=0`, `-trimpath` y timestamps del commit.

La ejecución nativa de aceptación se realiza en Linux amd64. En las otras plataformas se verifica el formato y arquitectura del ejecutable. Windows es experimental para las operaciones que requieren archivos privados: los controles POSIX `0600`/`0700` existentes no acreditan ACL equivalentes en Windows. F13 no introduce una implementación de ACL Windows ni afirma haber probado allí todas las funciones.

## Artefactos y comprobación

Para una versión `VERSION`, sin el prefijo `v` del tag:

- `secretwright_VERSION_OS_ARCH.tar.gz` o `.zip`: los seis archivos comprimidos.
- `secretwright_VERSION_OS_ARCH.spdx.json`: inventario SPDX de cada paquete, con identidad del producto y dependencias Go.
- `secretwright_VERSION_ARCH.deb`: los dos paquetes Debian, con el mismo ejecutable Linux verificado en el archivo comprimido.
- `secretwright_VERSION_ARCH.deb.spdx.json`: inventario SPDX de cada paquete Debian.
- `secretwright_VERSION_linux_multiarch.oci.tar`: imagen OCI para Linux amd64 y arm64.
- `secretwright_VERSION_linux_ARCH.image.spdx.json`: inventario de cada arquitectura de la imagen.
- `secretwright_VERSION_checksums.txt`: SHA-256 de esos diecinueve archivos.
- `secretwright_VERSION_checksums.sig`: firma Ed25519 del manifiesto completo.
- `secretwright_VERSION_signing-key.pem`: clave pública correspondiente al firmante.

El bundle contiene veintidós assets: diecinueve archivos cubiertos por el manifiesto, el propio manifiesto, su firma y la clave pública. La versión interna Debian convierte el primer guion de prerelease en `~`; por ejemplo, `0.1.0-rc.4` corresponde a `0.1.0~rc.4`, ordenada antes de la estable en Debian. Los nombres descargables y los inventarios conservan la identidad SemVer del producto. Así los nombres subidos a GitHub no contienen `~`, que el servicio reemplaza por un punto.

El verificador rechaza archivos ausentes o adicionales, symlinks, rutas inseguras y miembros duplicados en los paquetes. Comprueba las cabeceras ELF/Mach-O/PE, arquitectura, modo ejecutable Unix, inventarios y cobertura exacta del manifiesto. En Linux rechaza un intérprete dinámico y dependencias de bibliotecas compartidas. La imagen OCI debe contener exactamente las dos plataformas esperadas y sus blobs deben corresponder a sus digests.

La CI genera dos veces los archivos comprimidos y los paquetes `.deb` del mismo commit y compara sus bytes. Esta garantía se aplica a binarios y archivos de distribución; no se promete igualdad byte a byte de SBOM e imágenes, cuyos metadatos pueden incluir timestamps propios.

GoReleaser y Syft están fijados a versiones y hashes concretos. Syft escanea los artefactos locales sin enriquecimiento remoto. La firma usa OpenSSL Ed25519 y no requiere un servicio de transparencia público ni OIDC.

Una clave pública descargada junto a una firma necesita una referencia de confianza independiente. El usuario selecciona su clave pública confiable para verificar el manifiesto y después comprueba los hashes de los archivos descargados. La [guía de distribución](../distribution.md) detalla el procedimiento.

## Paquetes Debian

Los `.deb` instalan el ejecutable en `/usr/bin/secretwright`, con propietario root y modo `0755`, y `README.md` y la licencia en `/usr/share/doc/secretwright/README.md` y `copyright`, con modo `0644`. Declaran `ca-certificates` como dependencia. No incluyen scripts de mantenimiento, servicios, configuración ni secretos.

El verificador comprueba la estructura ar y los archivos control y data, el nombre del paquete, la versión Debian, la arquitectura, dependencias, permisos e integridad de los tres archivos instalados. Rechaza contenido adicional y comprueba que el ejecutable coincide con el del archivo Linux de esa arquitectura. Los dos paquetes tienen su propio inventario SPDX y quedan cubiertos por la firma del manifiesto SHA-256.

La aceptación instala y reinstala el paquete amd64 en Debian 13, comprueba la versión, los comandos offline y la integridad registrada por `dpkg`, y purga el paquete. El arm64 se verifica por estructura y arquitectura del binario; no se afirma ejecución nativa en arm64. La [guía de distribución](../distribution.md#debian) contiene los comandos de instalación y desinstalación.

## Imagen y archivos privados

La imagen usa Distroless Debian 13 estática con CA incluidas y una base fijada por digest. El pin se contrastó en los Dockerfiles de [Sigstore](https://github.com/sigstore/timestamp-authority/blob/e0733fa44b1b10e72a84314de74e9502cb4cdc47/Dockerfile) y [CloudNativePG](https://github.com/cloudnative-pg/cloudnative-pg/blob/7adba6a4a4bce29b16a93f7f67ce32d83c325631/Dockerfile). Contiene el binario, carece de shell y runtime Go y ejecuta por defecto como `65532:65532`. Se construye con binarios ya verificados; el contexto Docker solo permite esos binarios y el Dockerfile.

Los comandos offline funcionan con raíz de solo lectura y sin red. Los archivos `0600` del host requieren ejecutar con el UID/GID de su propietario y montar explícitamente los directorios necesarios. Las salidas privadas necesitan un montaje escribible. No se relajan los permisos del archivo para permitir su lectura desde el contenedor.

La aceptación ejecuta la imagen real: versión, ayuda, YAML offline, lectura de keytab privado, rechazo de archivo público, exportación privada y conflicto al sobrescribir. Un servidor TLS efímero comprueba CA explícita válida, CA no confiable y hostname incorrecto; la verificación TLS permanece activa.

## Publicación

Las ramas y PR generan snapshots sin publicar. Al mergear en `main`, el [flujo TBD](TBD-releases.md) selecciona una RC automática o la candidata indicada por una PR de promoción. El commit seleccionado debe pertenecer al historial de `main` y pasar la CI reutilizable completa con la versión final prevista, incluida la regresión F00–F12 y la aceptación de distribución. El publicador crea el tag después de verificar el bundle y la firma; los pushes de tags no disparan otro workflow.

El job de publicación consume el bundle del mismo run y commit. Antes de subir cualquier archivo exige una clave Ed25519 PKCS#8 cifrada válida y su contraseña, proporcionadas mediante `SECRETWRIGHT_SIGNING_KEY` y `SECRETWRIGHT_SIGNING_PASSWORD`. La clave privada permanece fuera del bundle y del contexto Docker. Las firmas efímeras de CI se sustituyen por la firma de release y se verifican de nuevo.

Una release existente no se sobrescribe. Los archivos se suben a un borrador y se publica cuando el conjunto está completo. Una interrupción puede dejar un borrador que requiere inspección; no hay borrado ni rollback automáticos. El archivo OCI se distribuye como asset firmado y no exige un registro de imágenes adicional.

La CI de ramas y PR prueba la firma con claves temporales; la publicación tras el merge usa los secretos de firma del proyecto.

## Aceptación

Las pruebas independientes del verificador introducen hashes incorrectos, archivos faltantes, duplicados, traversal, enlaces, arquitectura incorrecta, inventarios inválidos, metadatos Debian inconsistentes y contenido no permitido en los `.deb`. Las pruebas de firma usan OpenSSL real y rechazan un manifiesto alterado, una clave distinta y salidas existentes. La política de tags se prueba en repositorios Git temporales.

Después se ejecutan GoReleaser, Syft, los verificadores y Docker sobre los artefactos completos. Se conservan todos los controles previos: formato, módulos, vet, detector de carreras, seis fuzzers y los escenarios reales de Vault/PostgreSQL y CLI de F00–F12.
