Programa en JS que automatiza bloqueo de IP en VPS (Debian).

Nociones generales:
- Utilizará la información producida por el programa PSAD (en archivo /var/log/psad/status.out)
- Generará una "mini-base de datos" con archivos de txt, cuya información utilizará para determinar condiciones
- Utilizará ufw para bloquear IP según nivel de sospecha (usando API de AbuseDB)


PENDIENTE: Detallar requisitos (instalar PSAD, configurar PSAD y ufw, crear cuenta en AbuseDB
y crear clave API, ejecutar script recurrentemente con cron, etc.) y riesgos (bloqueo de IP
propia si se realiza escaneo de puertos).