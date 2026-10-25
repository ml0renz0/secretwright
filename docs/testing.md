# Pruebas y CI

El workflow `.github/workflows/ci.yml` se ejecuta en cada push, pull request y ejecución manual. Todos los jobs deben pasar para dar la entrega por verificada. Las ejecuciones usan Ubuntu 24.04 y Go 1.27.x; las pruebas reales utilizan un Vault de desarrollo efímero, con la imagen `hashicorp/vault:2.2.0` por defecto.

## Comprobaciones de código

`make check` exige formato gofmt, ejecuta `go vet`, todas las pruebas Go sin la etiqueta integration con `-race -count=1` y compila el binario con `CGO_ENABLED=0`. El workflow comprueba también los checksums y que `go mod tidy` no cambie los archivos de módulos.

Estas pruebas incluyen servidores HTTP y backends controlados para provocar errores que son difíciles de reproducir contra un servidor normal: respuestas truncadas, redirecciones, denegaciones, cancelaciones, escrituras inciertas y cambios concurrentes. Las comprobaciones de privacidad usan valores centinela para detectar credenciales o datos sensibles en informes y errores.

## Fuzzing

Tres jobs generan entradas adversariales durante 20 segundos cada uno, con el detector de carreras y dos workers. La minimización de cada entrada se limita a 100 ms para reservar el presupuesto de CI a explorar más casos. Las semillas del corpus se ejecutan también como regresiones en `make test`.

| Objetivo | Propiedades comprobadas |
| --- | --- |
| `FuzzLoad` | Lectura de blueprint y overrides sin pánicos; resultados deterministas, errores seguros y documentos válidos que conservan sus dependencias al revalidarse. |
| `FuzzRender` | Arquitecturas que producen un blueprint F07 válido y determinista, o un error fijo sin una salida parcial. |
| `FuzzResolvePath` | Navegación canónica bajo la raíz lógica, rechazo de caracteres ambiguos, estabilidad al reutilizar una ruta y ausencia de diagnósticos con la entrada rechazada. |

Se pueden ampliar localmente:

```bash
go test -race -run='^$' -fuzz='^FuzzLoad$' -fuzztime=2m -fuzzminimizetime=100ms -parallel=2 ./internal/blueprint
go test -race -run='^$' -fuzz='^FuzzRender$' -fuzztime=2m -fuzzminimizetime=100ms -parallel=2 ./internal/architecture
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

Los proxies de las pruebas reales inyectan cambios o cortan respuestas en puntos deterministas; las operaciones siguen llegando a Vault. Así se puede comprobar tanto el informe del cliente como el estado real que quedó en el servidor.

El laboratorio genera sus propios tokens, ignora las variables Vault del operador y elimina la fixture al terminar. Para ejecutar contra un laboratorio ya preparado, `make integration` requiere `VAULT_ADDR` y `VAULT_TEST_ROOT_TOKEN_FILE`.

## Alcance

No se exige un porcentaje de cobertura: la aceptación se basa en los contratos y sus regresiones observables. El workflow actual no contiene una matriz de sistemas operativos o versiones de Vault, ni reproduce un clúster HA, namespaces Enterprise o TLS entre nodos reales. Tampoco publica releases ni despliega servicios; es un workflow de CI.
