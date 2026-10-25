# Ejemplo de reconciliación

Estos archivos configuran un montaje KV v2 y una política ACL. No contienen ni crean valores secretos, tokens, SecretIDs o métodos de autenticación. Selecciona un Vault de laboratorio y un archivo de token de operador autorizado. Los nombres `reconciliation-demo` deben estar libres o coincidir exactamente con `base.yaml`.

El estado local debe conservarse fuera del control de versiones y con sus permisos `0600`. Los ejemplos usan `deployment.state.json`; puedes seleccionar otra ruta privada. La dirección configurada y el namespace deben conservarse durante el flujo porque forman parte del binding del inventario.

## Inicializar y crear

```bash
secretwright blueprint validate --file examples/reconciliation/base.yaml

secretwright blueprint adopt --file examples/reconciliation/base.yaml \
  --state deployment.state.json --token-file operator-token
secretwright blueprint plan --file examples/reconciliation/base.yaml \
  --state deployment.state.json --token-file operator-token
secretwright blueprint apply --file examples/reconciliation/base.yaml \
  --state deployment.state.json --token-file operator-token
```

La adopción solo registra recursos existentes equivalentes y omite los ausentes; en un laboratorio limpio crea un inventario vacío. No escribe en Vault. Apply crea los recursos ausentes y confirma sus registros. Un plan posterior del mismo archivo debe mostrar `changes: []`.

Si ya desplegaste este mismo blueprint mediante F07 sin `--state`, adopt permite reclamarlo de forma explícita. Los recursos existentes equivalentes que solo aparecen como noops durante apply no se incorporan silenciosamente al inventario.

## Cambiar la intención

`changed.yaml` conserva IDs, nombres y montaje; amplía únicamente las capacidades de datos de la política a create/read/update/delete dentro de `app/*`. No permite destruir historial ni administrar el montaje.

```bash
secretwright blueprint plan --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token
secretwright blueprint apply --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token
```

Sin drift externo, el plan identifica una actualización por cambio deseado. Tras aplicarla, el plan queda vacío.

## Detectar y reparar una modificación externa

Este paso altera deliberadamente la política del laboratorio con F06 para simular un cambio externo al inventario. `drift-policy.hcl` deniega el acceso a los datos de la aplicación.

```bash
secretwright policy write --file examples/reconciliation/drift-policy.hcl \
  --token-file operator-token reconciliation-demo-app

# Devuelve conflicto por drift; no cambia recursos ni baselines.
secretwright blueprint plan --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token

# Revisar antes de autorizar explícitamente su reparación.
secretwright blueprint plan --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --repair --token-file operator-token
secretwright blueprint apply --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --repair --token-file operator-token
```

La reparación restaura la política de `changed.yaml`. Si el recurso ya coincide con el descriptor pero su baseline cambió, `--repair` permite reconocerlo mediante un refresh local sin escritura Vault.

## Retener recursos omitidos

`retained.yaml` solo declara el montaje. La política registrada se muestra como `retain`, permanece en el inventario y no se borra ni consulta remotamente. No forma parte de `changes`.

```bash
secretwright blueprint plan --file examples/reconciliation/retained.yaml \
  --state deployment.state.json --token-file operator-token
```

Un plan vacío de cambios no demuestra ausencia de drift en recursos retenidos. F09 no incluye prune ni eliminación implícita.

## Recuperar una operación pendiente

Después de un resultado incierto, comprobar el informe y consultar explícitamente el estado:

```bash
secretwright blueprint recover --file examples/reconciliation/changed.yaml \
  --state deployment.state.json --token-file operator-token
```

Recover no escribe en Vault. Si una creación incierta ahora existe y es equivalente, hace falta repetirlo con `--adopt-pending` para reclamarla explícitamente; una actualización conserva sus comprobaciones de identidad. Si hay un lock abandonado, comprobar primero que no exista una operación activa antes de retirarlo.

No fabriques ni edites hashes del inventario para forzar una recuperación. El [contrato F09](../../docs/features/F09-reconciliation-drift.md) detalla las reglas de pending, checkpoint, códigos y límites de concurrencia.
