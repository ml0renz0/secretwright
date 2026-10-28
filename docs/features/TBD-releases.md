# RC y estables en desarrollo sobre main

## Flujo

El desarrollo usa ramas cortas y PR hacia `main`. La CI de cada PR comprueba la regresión funcional y la distribución sin publicar. El workflow `Release` coordina la validación del código seleccionado y su publicación después del merge.

| Cambio integrado en `main` | Código seleccionado | Publicación |
| --- | --- | --- |
| Desarrollo con `promote_candidate` sin cambios | Commit integrado | RC de `next_version` |
| PR que cambia únicamente el YAML para promover una RC | Commit de la RC publicada | Estable de la versión de esa RC |

Cada publicación ejecuta la CI completa sobre el commit seleccionado, incluidas las pruebas de Vault/PostgreSQL y la aceptación de los paquetes. El job de publicación consume el bundle de esa ejecución. Crear el tag forma parte del coordinador; no se depende de que el tag creado con `GITHUB_TOKEN` dispare otro workflow.

## Política versionada

`.github/release.yaml` declara la próxima versión y la última candidata seleccionada para promoción:

```yaml
next_version: 0.1.0
promote_candidate: null
```

Con esa política, un merge normal produce `v0.1.0-rc.N`, donde `N` es `GITHUB_RUN_NUMBER` del workflow `Release`. El número pertenece al workflow, no se reinicia para cada versión y puede tener saltos. Volver a ejecutar el mismo run conserva su número; una publicación existente no se sustituye.

La política admite dos campos planos obligatorios: `next_version` es una versión estable `MAJOR.MINOR.PATCH`; `promote_candidate` es `null` o una candidata `vMAJOR.MINOR.PATCH-rc.N`, con `N` positivo. Los componentes numéricos no tienen ceros iniciales. El orden de los campos es libre; se permiten líneas vacías, comentarios y comentarios inline tras un espacio y `#`. El fichero tiene un máximo de 4096 bytes. Se rechazan indentación, comillas, marcadores de documento, anchors, aliases, campos desconocidos y duplicados.

La próxima versión puede mantenerse o avanzar; no puede retroceder. No se incrementa automáticamente a partir de los mensajes de commit.

## Promoción a estable

Cuando una candidata publicada está aceptada, una PR que solo cambia `.github/release.yaml` selecciona esa candidata y abre el siguiente ciclo:

```yaml
next_version: 0.1.1
promote_candidate: v0.1.0-rc.4
```

El merge aprueba liberar `v0.1.0`. La candidata debe corresponder a la versión objetivo anterior (`0.1.0`), estar publicada como prerelease y apuntar a un commit del historial de `main`. El coordinador fija ese commit antes de compilar; el commit del merge de promoción controla la operación, pero no es el código fuente de la estable.

La versión final está incorporada al ejecutable. La estable se recompila desde el mismo commit de la candidata con `0.1.0` y pasa de nuevo la CI completa. Sus artefactos tienen bytes, hashes y firma nuevos. Cualquier avance posterior de `main` queda fuera de esa estable.

La próxima versión debe ser mayor que la estable promovida. La promoción no se combina con cambios de código: si hace falta una corrección, se integra en `main`, se valida su nueva RC y después se selecciona esa RC en otra PR de promoción.

En los merges posteriores se conserva `promote_candidate: v0.1.0-rc.4`. Al no cambiar ese campo, se generan RC de `0.1.1`. Una promoción se reconoce por el cambio respecto al primer padre del commit integrado, no por la mera presencia de un valor en ese campo.

## Publicación y fallos

Las claves de producción solo se entregan al job de publicación mediante `SECRETWRIGHT_SIGNING_KEY` y `SECRETWRIGHT_SIGNING_PASSWORD`. Primero se comprueban el bundle y la clave y se firma y verifica fuera de línea. Si faltan los secretos o la clave no sirve, no se crea el tag remoto ni la release.

El publicador exige que el tag y la release de destino no existan. Crea el tag con el commit validado, sube los veintidós assets a un borrador y verifica sus nombres, tamaños y SHA-256 antes de publicarlo. Vuelve a comprobar el tag antes de publicar. En una promoción también comprueba que la candidata publicada sigue apuntando al commit seleccionado.

Las RC se publican como prerelease y nunca como latest. Para las estables, GitHub selecciona latest con su política de fecha de creación y versión SemVer (`make_latest: legacy`); el publicador no fuerza una estable antigua como latest cuando dos promociones terminan fuera de orden. Los tags y las releases existentes no se sobrescriben. Un error tras una mutación puede dejar un tag o borrador que exige inspección; no se borran automáticamente ni se repite una publicación a ciegas.

La [guía de distribución](../distribution.md) contiene la configuración inicial de firma y los pasos del mantenedor. El [contrato F13](F13-packaging-release.md) conserva el formato de los artefactos y sus límites de plataforma.
