# Registro de seguridad · Sistema Alumnos

Estudiante: Vicente Alfaro   Repositorio: https://github.com/VicenteAlfaroS/Proyecto_alumnos_ciber.git   Fecha: 2026-11-23

Completa este registro a medida que avanzas. Cada fila debe poder seguirse hasta un **build de Jenkins**
y un **commit** (usa el identificador `VULN-xx` en el mensaje del commit).

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit en el pipeline | #3 | 2 High / 1 Medium / 1 Low (MD5, `debug=True`, bind `0.0.0.0`) |
| R2 | Dependencias (SCA) | pip-audit en el pipeline | #3 → #10 | 19 vulnerabilidades en 4 paquetes → 0 vulnerabilidades tras el PR de Dependabot |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP sobre staging | #3 | 2 High / 3 Medium / 1 Low |
| R4 | Revisión manual | Lectura de `app.py` | — | VULN-01 (SQLi), VULN-02 (XSS), VULN-03 (secretos/MD5), VULN-04 (debug/CSRF) |
| R5 | Producción | Grafana + Prometheus | — | Dashboard con 4 paneles, alerta *Muchos logins fallidos* en Firing e incidente registrado el 2026-11-23 18:55:53 |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | CWE-89 Inyección SQL | Revisión manual | `app.py:205` `/alumnos/buscar` | Alto | Consulta parametrizada `LIKE ?` y error 500 genérico (sin exponer la consulta) | `a468994` | #4 |
| VULN-02 | CWE-79 XSS reflejado | Revisión manual + OWASP ZAP | `app.py:154` `/hello` | Alto | `escape(name)` con `markupsafe` antes de devolver el HTML | `6dcaf5c` | #5 |
| VULN-03 | CWE-798 / CWE-916 Secretos hardcodeados y MD5 | Bandit + revisión manual | `app.py:21-27`, `/login` | Alto | Secretos por `APP_SECRET_KEY` / `ADMIN_PASSWORD_HASH` y `check_password_hash` (PBKDF2) | `b73638b` | #6 |
| VULN-04 | CWE-94 `debug=True` / CWE-352 CSRF / CWE-605 bind / CWE-307 fuerza bruta | Bandit + OWASP ZAP | `app.py:59-60, 147-152, 243-276, 285` | Medio/Alto | Token CSRF en sesión, `debug=False`, host por entorno, cabeceras CSP/X-Frame-Options/X-Content-Type-Options y límite de 10 intentos/min | `3e99bf4` | #7 |
| VULN-04b | CWE-693 CSP sin `form-action` / CWE-1275 cookie sin `SameSite` | OWASP ZAP (build #7) | `app.py:29-33`, `despues_de_la_peticion` | Medio/Bajo | `form-action 'self'` explícita en la CSP y `SESSION_COOKIE_SAMESITE=Lax` (la directiva `form-action` no hereda de `default-src`) | `69fa068` | #8 |

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
| 18:55:53 | *Logins fallidos (1 min)* · `sum(increase(login_fallidos_total{job="produccion"}[1m]))` | 10 intentos fallidos en menos de un minuto contra `/login`; después el servicio empezó a devolver `429` | Producción `http://localhost:5000` | Fuerza bruta de credenciales (CWE-307 / OWASP A07), criticidad media | Rate limit de 10 intentos/IP en 60 s (HTTP 429), verificación con PBKDF2 (`check_password_hash`) y token anti-CSRF | `login_fallidos_total = 10`; ~63 respuestas `429` en la ventana de 5 min; la alerta *Muchos logins fallidos (producción)* pasó a **Firing**; ninguna clave válida |
| 18:55:53 | *Peticiones sospechosas por tipo* · `sum by (tipo) (increase(peticiones_sospechosas_total{job="produccion"}[5m]))` | `sqli = 3`, `xss = 3`: payloads de inyección SQL y `<script>` contra `/alumnos/buscar` y `/hello` | Producción `http://localhost:5000` | Intentos de inyección SQL (CWE-89) y XSS reflejado (CWE-79), criticidad media | Consulta parametrizada `LIKE ?`, `escape(name)`, CSP con `form-action 'self'` y cabeceras de seguridad | La inyección no devolvió estructura de la BD y el script no se reflejó sin escapar; el panel mostró las Series `sqli`/`xss` y la métrica sigue contabilizando los intentos |
| 18:55:53 – 18:58 | *Versión desplegada* · `app_info{job="produccion"}` | Versión `1.0.8+69fa068`, confirmada también en `GET /version` | Producción `http://localhost:5000` | Trazabilidad del despliegue (información) | El gate de ZAP del build #8 permitió el deploy al quedar en `High=0, Medium=0` | `app_info{version="1.0.8+69fa068"} = 1` y `/version` devuelve la misma versión |

**Resumen del incidente (detección → análisis → clasificación → respuesta → verificación):**

- **Detección:** el dashboard de Grafana mostró un pico de `login_fallidos_total` y de `peticiones_sospechosas_total` en el job `produccion` a las 18:55:53. La regla *Muchos logins fallidos (producción)* superó el umbral de 5 fallos en 1 minuto y pasó a **Firing**, enviando la notificación al contact point `alertas-locales`.
- **Análisis:** el tráfico provenía del script `scripts/simular_ataque.py` ejecutado contra el entorno de laboratorio; combinó fuerza bruta en `/login`, un payload `UNION SELECT ... sqlite_master` en `/alumnos/buscar` y `<script>alert('xss')</script>` en `/hello`.
- **Clasificación:** criticidad media; fuerza bruta (CWE-307), inyección SQL (CWE-89) y XSS (CWE-79) sobre el entorno de producción del laboratorio.
- **Respuesta:** el control de rate limit bloqueó los intentos restantes con `429`; las correcciones de VULN-01 a VULN-04b impidieron la explotación (consulta parametrizada, escape de salida, hash PBKDF2, CSRF, cabeceras y CSP completa).
- **Verificación:** no se expuso la estructura de la base de datos ni se ejecutó el script inyectado; la alerta se disparó correctamente y el dashboard permitió correlacionar los picos con la versión `1.0.8+69fa068` desplegada.

## 5. Gestión de dependencias

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | PYSEC-2023-62, PYSEC-2026-2151 | 3.1.3 | PR #1 de Dependabot (grupo `python-dependencies`) | Sí, #10 |
| Werkzeug | 2.2.2 | PYSEC-2023-58, PYSEC-2023-57, PYSEC-2023-221, PYSEC-2026-2046/2045/2044/2043/2320/3417/4312 | 3.1.9 | PR #1 de Dependabot (grupo `python-dependencies`) | Sí, #10 |
| Jinja2 | 3.1.2 | PYSEC-2026-1473, 1471, 1474, 1475, 1472 | 3.1.6 | PR #1 de Dependabot (grupo `python-dependencies`) | Sí, #10 |
| gunicorn | 21.2.0 | PYSEC-2026-1434, PYSEC-2026-1433 | 27.0.1 | PR #1 de Dependabot (grupo `python-dependencies`) | Sí, #10 |
| prometheus-client | 0.17.1 | — (sin hallazgos en pip-audit) | 0.26.0 | PR #1 de Dependabot (actualización preventiva) | Sí, #10 |
| pytest (dev) | 8.3.4 | — (sin hallazgos en pip-audit) | 9.2.0 | PR #1 de Dependabot (grupo `python-dependencies`) | Sí, #10 |

**Proceso:** se añadió `.github/dependabot.yml` (commit `42b8e51`) con `package-ecosystem: pip`, `directory: "/"`, schedule `daily` y un grupo `python-dependencies` para concentrar todos los bumps en un único PR. Dependabot abrió el **PR #1** (`deps: bump the python-dependencies group with 6 updates`), que se mergeó en `43d8e7b`. El build **#10** verificó 9/9 pruebas, Bandit `0/0/0`, `pip-audit: 0 vuln.` y ZAP `0/0/0`, y desplegó la versión `1.0.10+43d8e7b`. El contenido de `reports/pip-audit.json` confirma `"vulns": []` y `"fixes": []` para todas las dependencias.

## 6. Trazabilidad

Pega aquí (o adjunta) el `TRAZABILIDAD.md` del último build y completa un recorrido por cada actividad del pipeline:

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | VULN-03, VULN-04 | #3 | `b73638b`, `3e99bf4` | #6, #7 | 1.0.10+43d8e7b |
| Revisión de seguridad (pip-audit) | 19 CVEs en 4 paquetes | #3 | PR #1 de Dependabot (`43d8e7b`) | #10 | 1.0.10+43d8e7b |
| Prueba automatizada (OWASP ZAP) | VULN-02 + VULN-04 (CSRF/headers) + VULN-04b (CSP/SameSite) | #3, #7 | `6dcaf5c`, `3e99bf4`, `69fa068` | #5, #7, #8 | 1.0.10+43d8e7b |
| Gestión de dependencias (Dependabot) | Dependencias vulnerables (Flask, Werkzeug, Jinja2, gunicorn) | #3 | `.github/dependabot.yml` (`42b8e51`) + PR #1 (`43d8e7b`) | #10 | 1.0.10+43d8e7b |
| Corrección manual (SQLi) | VULN-01 | #3 | `a468994` | #4 | 1.0.10+43d8e7b |
| Monitoreo e incidente | Fuerza bruta + intentos SQLi/XSS en producción | Grafana (18:55:53) | Controles de VULN-01 a VULN-04b + bloqueo 429 | Dashboard y alerta en Firing | 1.0.8+69fa068 |

> El build #10 dejó el pipeline en verde con `Bandit 0/0/0`, `pip-audit 0 vuln.`, `ZAP 0/0/0`,
> `9/9 OK` y `Finished: SUCCESS`. El artefacto `reports/trazabilidad-build.md` resume cada build
> con su versión, commit y resultado.
