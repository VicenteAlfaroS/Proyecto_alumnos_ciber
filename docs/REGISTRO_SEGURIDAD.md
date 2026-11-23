# Registro de seguridad · Sistema Alumnos

Estudiante: Vicente Alfaro   Repositorio: https://github.com/VicenteAlfaroS/Proyecto_alumnos_ciber.git   Fecha: 2026-11-23

Completa este registro a medida que avanzas. Cada fila debe poder seguirse hasta un **build de Jenkins**
y un **commit** (usa el identificador `VULN-xx` en el mensaje del commit).

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit en el pipeline | #3 | 2 High / 1 Medium / 1 Low (MD5, `debug=True`, bind `0.0.0.0`) |
| R2 | Dependencias (SCA) | pip-audit en el pipeline | #3 | 19 vulnerabilidades en 4 paquetes |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP sobre staging | #3 | 2 High / 3 Medium / 1 Low |
| R4 | Revisión manual | Lectura de `app.py` | — | VULN-01 (SQLi), VULN-02 (XSS), VULN-03 (secretos/MD5), VULN-04 (debug/CSRF) |
| R5 | Producción | Grafana + Prometheus | — | Pendiente (evidencias 7–9) |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | CWE-89 Inyección SQL | Revisión manual | `app.py:205` `/alumnos/buscar` | Alto | Consulta parametrizada `LIKE ?` y error 500 genérico (sin exponer la consulta) | `a468994` | #4 |
| VULN-02 | CWE-79 XSS reflejado | Revisión manual + OWASP ZAP | `app.py:154` `/hello` | Alto | `escape(name)` con `markupsafe` antes de devolver el HTML | `6dcaf5c` | #5 |
| VULN-03 | CWE-798 / CWE-916 Secretos hardcodeados y MD5 | Bandit + revisión manual | `app.py:21-27`, `/login` | Alto | Secretos por `APP_SECRET_KEY` / `ADMIN_PASSWORD_HASH` y `check_password_hash` (PBKDF2) | `b73638b` | #6 |
| VULN-04 | CWE-94 `debug=True` / CWE-352 CSRF / CWE-605 bind / CWE-307 fuerza bruta | Bandit + OWASP ZAP | `app.py:59-60, 147-152, 243-276, 285` | Medio/Alto | Token CSRF en sesión, `debug=False`, host por entorno, cabeceras CSP/X-Frame-Options/X-Content-Type-Options y límite de 10 intentos/min | `3e99bf4` | #7 |
| VULN-04b | CWE-693 CSP sin `form-action` / CWE-1275 cookie sin `SameSite` | OWASP ZAP (build #7) | `app.py:29-33`, `despues_de_la_peticion` | Medio/Bajo | `form-action 'self'` explícita en la CSP y `SESSION_COOKIE_SAMESITE=Lax` (la directiva `form-action` no hereda de `default-src`) | `VULN-04b` | #8 |

> VULN-04b es un seguimiento de VULN-04: el build #7 mitigó XSS, CSRF y los headers, pero ZAP siguió
> reportando un Medium porque `form-action` no tiene fallback a `default-src`, por lo que el gate de
> producción omitió el deploy. Se corrige en el build #8.

## 3. Resultados de OWASP ZAP

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| Cross Site Scripting (Reflected) | High | `/hello?name=<script>alert(1)</script>` | VULN-02 | `escape(name)` en la respuesta HTML | Sí, #5 |
| Cross Site Scripting (DOM Based) | High | `/hello?name=<script>alert(5397)</script>` | VULN-02 | `escape(name)` en la respuesta HTML | Sí, #5 |
| Absence of Anti-CSRF Tokens | Medium | `/`, `/login` | VULN-04 | Token anti-CSRF en el formulario y validación en `/login` | Sí, #7 |
| Content Security Policy (CSP) Header Not Set | Medium | `/` | VULN-04 | Añadir cabecera `Content-Security-Policy` | Sí, #7 |
| Missing Anti-clickjacking Header | Medium | `/` | VULN-04 | Añadir `X-Frame-Options: DENY` | Sí, #7 |
| X-Content-Type-Options Header Missing | Low | `/` | VULN-04 | Añadir `X-Content-Type-Options: nosniff` | Sí, #7 |
| CSP: Failure to Define Directive with No Fallback | Medium | `/` | VULN-04b | Declarar `form-action 'self'` explícitamente (no hereda de `default-src`) | Sí, #8 |
| Cookie without SameSite Attribute | Low | `/` | VULN-04b | `SESSION_COOKIE_SAMESITE = "Lax"` | Sí, #8 |

> Observación: la inyección SQL (VULN-01) no fue reportada por ZAP; se identificó en la revisión manual
> y se corrigió en el build #4.

## 4. Monitoreo e incidentes

| Hora | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| | | | | | | |

## 5. Gestión de dependencias

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | PYSEC-2023-62, PYSEC-2026-2151 | | | |
| Werkzeug | 2.2.2 | PYSEC-2023-58, PYSEC-2023-57, PYSEC-2023-221, PYSEC-2026-* | | | |
| Jinja2 | 3.1.2 | PYSEC-2026-1473, 1471, 1474, 1475, 1472 | | | |
| gunicorn | 21.2.0 | PYSEC-2026-1434, PYSEC-2026-1433 | | | |
| prometheus-client | 0.17.1 | — (sin hallazgos en pip-audit) | | | |

## 6. Trazabilidad

Pega aquí (o adjunta) el `TRAZABILIDAD.md` del último build y completa un recorrido por cada actividad del pipeline:

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | VULN-03, VULN-04 | #3 | `b73638b`, `3e99bf4` | #6, #7 | — |
| Revisión de seguridad (pip-audit) | 19 CVEs en 4 paquetes | #3 | — | — | — |
| Prueba automatizada (OWASP ZAP) | VULN-02 + VULN-04 (CSRF/headers) + VULN-04b (CSP/SameSite) | #3, #7 | `6dcaf5c`, `3e99bf4`, `VULN-04b` | #5, #7, #8 | — |
| Gestión de dependencias (Dependabot) | Pendiente | — | — | — | — |
| Corrección manual (SQLi) | VULN-01 | #3 | `a468994` | #4 | — |
