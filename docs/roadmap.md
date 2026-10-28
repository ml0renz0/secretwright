# Roadmap de Secretwright

Este roadmap conserva las fases acordadas para la evolución de VCLI. Secretwright es el nuevo proyecto Go; VCLI queda como referencia histórica. Los nombres que incluyen «Forge» identifican provisionalmente el motor declarativo, no un producto separado.

F00–F13 están integradas y las candidatas de `0.1.0` ya se publican en [Releases](https://github.com/ml0renz0/secretwright/releases), con [notas y alcance](releases/v0.1.0-rc.1.md). El siguiente hito es validar la primera estable con el [playground de Vault precargado](../examples/playground/README.md). El [flujo TBD de releases](features/TBD-releases.md) automatiza las RC al integrar cambios en `main` y las estables mediante PR de promoción. La [guía de distribución](distribution.md) describe la configuración de firma y la publicación.

| Fase | Título | Alcance previsto | Estado |
| --- | --- | --- | --- |
| **F00** | **Bootstrap y CI/CD Base** | Estructura del proyecto Go, compilación, GitHub Actions, primer Vault efímero y framework reutilizable de pruebas de integración. | Integrada — [PR #1](https://github.com/ml0renz0/secretwright/pull/1) |
| **F01** | **Vault Connectivity & Authentication** | Cliente Vault, configuración, TLS, tokens, autenticación, namespaces y gestión de conexiones. | Integrada — [PR #2](https://github.com/ml0renz0/secretwright/pull/2) |
| **F02** | **KV Storage: Read & Navigation** | Soporte KV v1/v2, detección de mounts, `ls`, `cd`, `cat`, navegación y resolución de rutas. | Integrada — [PR #3](https://github.com/ml0renz0/secretwright/pull/3) |
| **F03** | **KV Storage: Write & Versioning** | `put`, `rm`, `cp`, `mv`, gestión de versiones KV v2, recuperación de secretos y operaciones seguras. | Integrada — [PR #4](https://github.com/ml0renz0/secretwright/pull/4), [contrato](features/F03-kv-write-versioning.md) |
| **F04** | **Interactive Shell** | REPL, prompt, historial seguro, autocompletado remoto, búsqueda interactiva del historial y ejecución no interactiva. | Integrada — [PR #5](https://github.com/ml0renz0/secretwright/pull/5), [contrato](features/F04-interactive-shell.md) |
| **F05** | **Advanced Secret Operations** | `tree`, `find`, `replace`, `cptree`, `rmtree`, concurrencia controlada, backup y restore. | Integrada — [PR #6](https://github.com/ml0renz0/secretwright/pull/6), [contrato](features/F05-advanced-secret-operations.md) |
| **F06** | **Access & Identity Management** | Políticas ACL, AppRoles, RoleID/SecretID, gestión de identidades, permisos, emisión y revocación de credenciales. | Integrada — [PR #7](https://github.com/ml0renz0/secretwright/pull/7), [contrato](features/F06-access-identity-management.md) |
| **F07** | **Forge: Blueprint Engine** | Descriptor YAML, JSON Schema, variables, dependencias, `validate`, `plan`, `apply` e idempotencia. | Integrada — [PR #8](https://github.com/ml0renz0/secretwright/pull/8), [contrato](features/F07-blueprint-engine.md) |
| **F08** | **Forge: Architecture Templates** | Blueprints monousuario, multiusuario, monoapp, multiapp, multientorno y SaaS multi-tenant. Composición de patrones. | Integrada — [PR #10](https://github.com/ml0renz0/secretwright/pull/10), [contrato](features/F08-architecture-templates.md) |
| **F09** | **Forge: Reconciliation & Drift** | Inventario local de propiedad, adopción explícita, cambios deseados, drift bloqueado por defecto, reparación autorizada, recursos retenidos y recuperación de checkpoints. | Integrada — [PR #11](https://github.com/ml0renz0/secretwright/pull/11), [contrato](features/F09-reconciliation-drift.md) |
| **F10** | **Secrets Lifecycle & Rotation** | Rotación AppRole hacia un archivo privado, confirmación externa antes de retirar, TTL, renovación de tokens y leases exactos, recuperación ante fallos y YAML por defecto. | Integrada — [PR #12](https://github.com/ml0renz0/secretwright/pull/12), [contrato](features/F10-lifecycle-rotation.md) |
| **F11** | **X.509 & PKI Management** | Inspección de certificados, claves y CSR; SAN, cadena, caducidades, usos y clave correspondiente; generación local y emisión/firma/revocación mediante PKI Vault existente. | Integrada — [PR #13](https://github.com/ml0renz0/secretwright/pull/13), [contrato](features/F11-x509-pki.md) |
| **F12** | **Kerberos & Keytab Management** | Lector MIT v2, principales/KVNO/cifrados, política explícita y custodia binaria en Vault KV v2 con CAS y revisiones exactas, sin `klist`. | Integrada — [PR #14](https://github.com/ml0renz0/secretwright/pull/14), [contrato](features/F12-kerberos-keytab.md) |
| **F13** | **Packaging, Releases & Distribution** | Binarios autocontenidos, builds multiplataforma, imágenes Docker mínimas, GoReleaser, SBOM, firma de artefactos y documentación. | Integrada — [PR #15](https://github.com/ml0renz0/secretwright/pull/15), [contrato](features/F13-packaging-release.md) |

## Ciclo de cada fase

```text
Contrato funcional → Pruebas + CI/CD → Implementación
                                          ↓
                         Validación E2E → Regresión → Merge
```

F00 solo construye la infraestructura mínima de pruebas. Cada fase posterior amplía el CI/CD con sus propios escenarios reales antes de desarrollar la funcionalidad correspondiente.

Los escenarios comprobarán resultados funcionales. Por ejemplo, la futura gestión de accesos deberá demostrar permisos concedidos y denegados contra Vault real; los futuros blueprints deberán producir un plan vacío después de aplicar el mismo estado deseado; y la futura rotación deberá comprobar que el consumidor puede utilizar las credenciales nuevas.

## Principios de diseño

- Un único binario Go para las funciones principales y una experiencia de shell, con comandos también utilizables en automatizaciones.
- Cliente oficial de Vault, TLS verificado y configuración explícita de confianza cuando sea necesaria.
- Compatibilidad progresiva con el comportamiento útil de VCLI, revisando las operaciones que manejan información sensible.
- Blueprints de estado deseado que relacionen almacenamiento, accesos y ciclo de vida mediante recursos lógicos.
- Gestión de recursos separada de la emisión y rotación de credenciales sensibles.
- Ningún valor secreto en el futuro estado declarativo persistente y ninguna eliminación implícita de recursos ajenos.
- Pruebas de integración con Vault real, incluyendo aislamiento, errores y fallos parciales según se incorporen las funciones.
- Ejecución central independiente de Kubernetes, sin un daemon obligatorio ni frameworks extensos introducidos por anticipado.

La compatibilidad con OpenBao podrá estudiarse en una fase posterior; todavía no forma parte de la compatibilidad probada.
