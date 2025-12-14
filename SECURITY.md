# Política de Seguridad de OSINT-NG

## Reporte de Vulnerabilidades

Agradezco a los investigadores de seguridad por ayudar a mantener seguro a OSINT-NG. Si descubre una vulnerabilidad de seguridad, te pido que la reporte de manera responsable a través de mi programa de divulgación coordinada.

### Cómo Reportar una Vulnerabilidad

1. **Contacto**: Envíe un correo electrónico a [rodrigolopezpizarro271@gmail.com](mailto:rodrigolopezpizarro271@gmail.com) con el asunto "[OSINT-NG] Reporte de Vulnerabilidad".

2. **Incluya en su reporte**:
   - Descripción detallada de la vulnerabilidad
   - Pasos para reproducir el problema
   - Impacto potencial de la vulnerabilidad
   - Cualquier prueba de concepto o código de explotación
   - Su información de contacto

3. **Tiempo de Respuesta**:
   - Recibirá un acuse de recibo dentro de las 48 horas
   - Evaluaremos su reporte y nos pondremos en contacto con usted para cualquier aclaración
   - Le mantendremos informado sobre el progreso hacia una solución

### Política de Divulgación Responsable

- No divulgue públicamente la vulnerabilidad hasta que se haya solucionado y se haya lanzado una versión estable
- Permítanos un tiempo razonable para corregir la vulnerabilidad antes de cualquier divulgación pública
- Trabajaremos con usted para coordinar la divulgación pública si es necesario

## Seguridad en el Uso de OSINT-NG

### Configuración Segura

1. **API Keys**:
   - Nunca comparta sus claves de API
   - Utilice variables de entorno o archivos de configuración seguros
   - Revoke las claves comprometidas inmediatamente

2. **Permisos**:
   - Ejecute el script con los privilegios mínimos necesarios
   - No ejecute el script como usuario root a menos que sea absolutamente necesario

3. **Almacenamiento de Datos**:
   - Los datos sensibles se almacenan en `~/.config/osint-ng/`
   - Asegúrese de que los permisos de estos archivos sean restrictivos

### Mejores Prácticas

1. **Actualizaciones**:
   - Mantenga OSINT-NG actualizado a la última versión estable
   - Suscríbase a las notificaciones de seguridad del proyecto

2. **Redes y Conexiones**:
   - Utilice conexiones seguras (HTTPS, VPN) al realizar consultas
   - Sea consciente de las políticas de uso de las APIs y fuentes de datos

3. **Auditoría**:
   - Revise regularmente los logs y resultados del sistema
   - Monitoree el uso de sus claves de API

## Historial de Seguridad

- **2023-12-14**: Versión inicial de la política de seguridad

## Contacto de Seguridad

Para asuntos de seguridad, contacte directamente al equipo de seguridad en [seguridad@osint-ng.com](mailto:rodrigolopezpizarro271@gmail.com).

## Agradecimientos

Agradecemos a todos los investigadores que han contribuido a mejorar la seguridad de OSINT-NG a través de reportes responsables.

---
*Última actualización: Diciembre 2023*
