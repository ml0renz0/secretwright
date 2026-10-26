# Pruebas y CI

El workflow `.github/workflows/ci.yml` se ejecuta en cada push, pull request y ejecución manual. Todos los jobs deben pasar para dar la entrega por verificada. Las ejecuciones usan Ubuntu 24.04 y Go 1.27.x; las pruebas reales utilizan un Vault de desarrollo efímero, con la imagen `hashicorp/vault:2.2.0` por defecto.

## Comprobaciones de código

`make check` exige formato gofmt, ejecuta `go vet`, todas las pruebas Go sin la etiqueta integration con `-race -count=1` y compila el binario con `CGO_ENABLED=0`. El workflow comprueba también los checksums y que `go mod tidy` no cambie los archivos de módulos.

Estas pruebas incluyen servidores HTTP y backends controlados para provocar errores que son difíciles de reproducir contra un servidor normal: respuestas truncadas, redirecciones, denegaciones, cancelaciones, escrituras inciertas y cambios concurrentes. Las comprobaciones de privacidad usan valores centinela para detectar credenciales o datos sensibles en informes y errores.

## Fuzzing

Cuatro jobs generan entradas adversariales durante 20 segundos cada uno, con el detector de carreras y dos workers. La minimización de cada entrada se limita a 100 ms para reservar el presupuesto de CI a explorar más casos. Las semillas del corpus se ejecutan también como regresiones en `make test`.

| Objetivo | Propiedades comprobadas |
| --- | --- |
| `FuzzLoad` | Lectura de blueprint y overrides sin pánicos; resultados deterministas, errores seguros y documentos válidos que conservan sus dependencias al revalidarse. |
| `FuzzRender` | Arquitecturas que producen un blueprint F07 válido y determinista, o un error fijo sin una salida parcial. |
| `FuzzDecode` | Inventarios JSON estrictos, decodificación determinista, errores fijos y serialización de estados válidos que conserva su contenido. |
| `FuzzResolvePath` | Navegación canónica bajo la raíz lógica, rechazo de caracteres ambiguos, estabilidad al reutilizar una ruta y ausencia de diagnósticos con la entrada rechazada. |

Se pueden ampliar localmente:

```bash
go test -race -run='^$' -fuzz='^FuzzLoad$' -fuzztime=2m -fuzzminimizetime=100ms -parallel=2 ./internal/blueprint
go test -race -run='^$' -fuzz='^FuzzRender$' -fuzztime=2m -fuzzminimizetime=100ms -parallel=2 ./internal/architecture
go test -race -run='^$' -fuzz='^FuzzDecode$' -fuzztime=2m -fuzzminimizetime=100ms -parallel=2 ./internal/managedstate
go test -race -run='^$' -fuzz='^FuzzResolvePath$' -fuzztime=2m -fuzzminimizetime=100ms -parallel=2 ./internal/vault
```

Si el fuzzer encuentra un fallo, Go guarda la entrada en `testdata/fuzz`; Actions conserva ese corpus como artefacto durante siete días. Para reproducirlo se utiliza el comando que imprime Go. El presupuesto de CI es acotado y no sustituye las regresiones explícitas de las operaciones de escritura.

## Vault real y ejecutable

`make integration-local` inicia el servidor, crea sus credenciales de prueba y ejecuta `go test -race -count=1 -tags=integration ./...`. Esa orden incluye también las pruebas unitarias. Después compila el binario y ejecuta los smokes CLI y las sesiones con pseudoterminal.

| Área | Escenarios de regresión |
| --- | --- |
| Conexión y autenticación | Estado, selección de credenciales y namespace, tokens válidos, inválidos, revocados y expirados, TLS y timeouts en clientes controlados. |
| KV v1/v2 | Lectura, listado, navegación, permisos, CAS, versiones, delete/undelete, rollback, destrucción, copy y move. |
| Operaciones recursivas | Preflight, dry-run, comparación JSON exacta, conflictos entre lectura y escritura, conservación del historial borrado al restaurar y parada ante resultados parciales o inciertos. |
| Shell | Batch/script, PTY real, Tab, Ctrl+R, Ctrl+C, restauración del terminal, historial filtrado y nombres remotos sin ejecución de secuencias de control. |
| Accesos | Políticas y permisos efectivos, límites de uso de SecretID y tokens, revocación de descendientes, cambios de ACL en tokens ya emitidos, grupos y publicación de credenciales en archivos privados. |
| Blueprints | Validación offline, variables tipadas, DAG, conflictos y denegaciones antes de escribir, seis creaciones reales, UUIDs dependientes, plan posterior vacío y segunda aplicación con cero escrituras. |
| Templates de arquitectura | Seis patrones, composición con montaje compartido, render offline, IDs estables, expansión acotada, aislamiento entre usuarios/apps/entornos/tenants y aplicación idempotente con F07. Los aliases de usuarios son exclusivos de la fixture. |
| Reconciliación | Adopción explícita, inventario privado, binding de destino, cambios propios, drift bloqueado y reparación autorizada, recursos retenidos, identidad estable, referencias a nuevas identidades, checkpoints pendientes y recuperación sin escrituras Vault. |
| Ciclo de vida | Rotación AppRole con probe KV efectivo, publicación del token nuevo, anterior válido hasta confirmación explícita y revocado después, probe fallido sin cambiar consumidor, noops/dry-run, recuperación sin replay y TTL real tras renovar tokens. |
| Leases | PostgreSQL efímero con credenciales dinámicas: lookup, renovación de TTL, conexión SQL antes de revocar y autenticación rechazada después. El lease exacto y las credenciales nunca aparecen en informes. |
| YAML/JSON | Seis templates generan YAML por defecto o JSON explícito; los blueprints resultantes se revalidan y conservan tipos, enteros y HCL. Configuraciones y recibos lifecycle admiten ambos formatos. |

Los proxies de las pruebas reales inyectan cambios o cortan respuestas en puntos deterministas; las operaciones siguen llegando a Vault. Así se puede comprobar tanto el informe del cliente como el estado real que quedó en el servidor.

F09 añade comprobaciones del inventario local: JSON estricto, límites, archivos `0600`, exclusividad del lock, snapshots separados, detección de reemplazos y revisión incremental de checkpoints. La aceptación de backend verifica conservación de RoleID, SecretIDs, alias metadata, CIDRs, metadata y aliases no administrados, además de ausencia de HCL o credenciales en inventario e informes. Las APIs sin CAS conservan una carrera entre lectura y escritura; estos tests no acreditan exclusividad remota ni detección de una política borrada y recreada idéntica.

F10 comprueba también recibos y artefactos privados, exclusión de locks, reemplazos externos, preservación de UID/GID del consumidor, fases inciertas y ausencia de reintentos de emisión o login. La prueba de credenciales no demuestra recarga de una aplicación: ese paso exige una confirmación externa antes de retire.

El laboratorio genera sus propios tokens, ignora las variables Vault del operador y elimina la fixture al terminar. CI activa `VAULT_TEST_REQUIRE_DATABASE=1`: la ausencia de Docker o de la fixture PostgreSQL falla el job. El fallback local con un binario Vault sin Docker omite explícitamente las pruebas de base de datos. Para ejecutar contra un laboratorio ya preparado, `make integration` requiere `VAULT_ADDR` y `VAULT_TEST_ROOT_TOKEN_FILE`; las variables de la fixture PostgreSQL se documentan en `scripts/integration.sh`.

## Alcance

No se exige un porcentaje de cobertura: la aceptación se basa en los contratos y sus regresiones observables. El workflow actual no contiene una matriz de sistemas operativos o versiones de Vault, ni reproduce un clúster HA, namespaces Enterprise o TLS entre nodos reales. Tampoco publica releases ni despliega servicios; es un workflow de CI.
