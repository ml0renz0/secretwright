# Roadmap de Secretwright

Este roadmap conserva las fases acordadas para la evolución de VCLI. Secretwright es el nuevo proyecto Go; VCLI queda como referencia histórica. Los nombres que incluyen «Forge» identifican provisionalmente el motor declarativo, no un producto separado.

F00 es la fase de arranque. Las demás fases son planificación pendiente: su presencia en este documento no implica que esas funciones estén implementadas.

| Fase | Título | Alcance previsto | Estado |
| --- | --- | --- | --- |
| **F00** | **Bootstrap y CI/CD Base** | Estructura del proyecto Go, compilación, GitHub Actions, primer Vault efímero y framework reutilizable de pruebas de integración. | En desarrollo |
| **F01** | **Vault Connectivity & Authentication** | Cliente Vault, configuración, TLS, tokens, autenticación, namespaces y gestión de conexiones. | Pendiente |
| **F02** | **KV Storage: Read & Navigation** | Soporte KV v1/v2, detección de mounts, `ls`, `cd`, `cat`, navegación y resolución de rutas. | Pendiente |
| **F03** | **KV Storage: Write & Versioning** | `put`, `rm`, `cp`, `mv`, gestión de versiones KV v2, recuperación de secretos y operaciones seguras. | Pendiente |
| **F04** | **Interactive Shell** | REPL, prompt, historial seguro, autocompletado remoto, búsqueda interactiva y ejecución no interactiva. | Pendiente |
| **F05** | **Advanced Secret Operations** | `tree`, `find`, `replace`, operaciones recursivas, concurrencia controlada, backup y restore. | Pendiente |
| **F06** | **Access & Identity Management** | Políticas ACL, AppRoles, RoleID/SecretID, gestión de identidades, permisos, emisión y revocación de credenciales. | Pendiente |
| **F07** | **Forge: Blueprint Engine** | Descriptor YAML, JSON Schema, variables, dependencias, `validate`, `plan`, `apply` e idempotencia. | Pendiente |
| **F08** | **Forge: Architecture Templates** | Blueprints monousuario, multiusuario, monoapp, multiapp, multientorno y SaaS multi-tenant. Composición de patrones. | Pendiente |
| **F09** | **Forge: Reconciliation & Drift** | Detección de cambios externos, reconciliación, propiedad de recursos, planes de modificación y protección frente a eliminaciones accidentales. | Pendiente |
| **F10** | **Secrets Lifecycle & Rotation** | Rotación de credenciales, TTL, leases, políticas de mantenimiento, adaptadores externos y recuperación ante fallos. | Pendiente |
| **F11** | **X.509 & PKI Management** | Gestión y análisis de certificados, claves privadas, SAN, caducidades y validación criptográfica mediante Go, sin OpenSSL externo. | Pendiente |
| **F12** | **Kerberos & Keytab Management** | Lectura y validación de keytabs, principales, KVNO, tipos de cifrado e integración con Vault, sin `klist` externo. | Pendiente |
| **F13** | **Packaging, Releases & Distribution** | Binarios autocontenidos, builds multiplataforma, imágenes Docker mínimas, GoReleaser, SBOM, firma de artefactos y documentación. | Pendiente |

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
