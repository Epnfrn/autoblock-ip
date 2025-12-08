
## Pendientes

- A: Sistema de eliminación de reglas ufw después de cierto tiempo (porque acumular miles de reglas en ufw reducirá el rendimiento de la VPS, ya que los paquetes de datos deben ser analizados iterando a lo largo de todas las reglas ufw definidas).
- A: Funciones que creen los archivos correspondientes a los archivos de txt de forma programática, en caso de que NO existan; y si SÍ existen modificarlos (así al hacer git fetch esto NO sobreescribe el contenido de estos archivos, lo que puede borrar las IP bloqueadas). Considerar programas más eficientes, ej. ipset (ya que usa hash tables con O(1), a diferencia de ufw que usa listas lineales con O(n)).