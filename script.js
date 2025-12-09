
// Librerías
const { exec, execSync } = require('child_process');
const fs = require('fs/promises'); // Para manejar I/O de archivos asíncrono
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, ".env") });


// Constantes globales
const WHITELIST_FILE = path.join(__dirname, 'whitelist.txt');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.txt');
const TEMP_IGNORE_LIST_FILE = path.join(__dirname, 'temp-ignore-list.txt');
// El archivo de salida real del comando /usr/sbin/psad debe ser el especificado.
const PSAD_OUTPUT_PATH = path.join(__dirname, "psad-ip-list.txt");

const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/T/, '_').split('.')[0];   // Ej. "2025-12-08T03-26-57"
const LOGS_FOLDER = path.join(__dirname, "logs");
const LOG_FILE = path.join(__dirname, "logs", `autoblock-ip_${timestamp}.log`);

const ABUSEDB_API_KEY = process.env.ABUSEDB_API_KEY; // La clave API va aquí (CENSORED)
const url = "https://api.abuseipdb.com/api/v2/check";


// Funciones helper

// Sacada de IA. Ejecutar comando /usr/sbin/psad -S | grep -oP '^SRC:\s+\K[\d\.]+' > /opt/autoblock-ip/psad-ip-list.txt
//   y almacenar su output en archivo de texto psad-ip-list.txt
async function usePSADAndOverwriteTextFile() {
    const command = `/usr/sbin/psad -S | grep -oP '^SRC:\\s+\\K[\\d\\.]+' > ${PSAD_OUTPUT_PATH}`;    // se usa la dirección absoluta del comando para prevenir errores en el cronjob (que webea con las direcciones relativas)
    
    try {
        await new Promise((resolve, reject) => {
            exec(command, { shell: true }, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolve(stdout);
            });
        });
        await log(`Comando '${command}' ejecutado correctamente. El archivo ${PSAD_OUTPUT_PATH} ha sido sobreescrito.`, "ÉXITO");
    } 
    catch (error) {
        await log(`Error al ejecutar el comando: ${error.message}`, "ERROR");
        throw error;
    }
}

// Sacada de IA. Abrir archivo de texto (listas de IP), y luego crear un set con su contenido
async function loadIPSet(filename) {
    try {
        const content = await fs.readFile(filename, 'utf-8');
        // Dividir por saltos de línea, filtrar líneas vacías y crear un Set
        return new Set(
            content
                .split(/\r?\n/)
                .map(line => line.trim())
                .filter(line => line.length > 0)
        );
    } 
    catch (error) {
        if (error.code === 'ENOENT') {
            return new Set();
        }
        await log(`Error al cargar el archivo ${filename}: ${error.message}`, "ERROR");
        return new Set();
    }
}

// Sacada de IA. Bloquea IP (con ufw)
async function blockIP(ip) {
    try {
        // Ejecuta comando ufw deny from <SUSPICIOUS_IP>
        execSync(`/usr/sbin/ufw deny from ${ip}`);
        await log(`Blocked IP ${ip}`, "ÉXITO");
    } 
    catch (error) {
        await log(`Failed to block IP: ${ip}. Error: ${error.message.trim()}`, "ERROR");
    }
}

// Sacada de IA. Agrega IP bloqueada en archivo blacklist.txt
async function saveIPToBlacklist(ip) {
    // Reemplazando la función original con una versión que usa promesas.
    try {
        await fs.appendFile(BLACKLIST_FILE, ip + '\n', 'utf-8');
    } 
    catch (error) {
        await log(`Error al guardar IP en ${BLACKLIST_FILE}: ${error.message}`, "ERROR");
    }
}

// Agrega IP "NO sospechosa" (puntaje < 50) en archivo temp-ignore-list.txt
async function saveIPToTempIgnoreList(ip) {
    // Reemplazando la función original con una versión que usa promesas.
    try {
        await fs.appendFile(TEMP_IGNORE_LIST_FILE, ip + '\n', 'utf-8');
    } 
    catch (error) {
        await log(`Error al guardar IP en ${TEMP_IGNORE_LIST_FILE}: ${error.message}`, "ERROR");
    }
}

// Sacada de IA. Hace petición GET a la API de AbuseIPDB con una IP, y si es sospechosa, produce un valor verdadero
async function isSuspiciousIP(ip) {
    // Parámetros codificados en la URL
    const params = new URLSearchParams({
        ipAddress: ip,
        maxAgeInDays: '90',
        verbose: ''
    });
    const full_url = `${url}?${params.toString()}`;

    // Chequeo de error (variable entorno NO definida)
    if (typeof ABUSEDB_API_KEY === "undefined") {
        await log("Variable de entorno NO definida.", "ERROR");
        process.exit(1);
    }

    // Encabezados necesarios
    const headers = {
        "Key": ABUSEDB_API_KEY,
        "Accept": "application/json"
    };

    try {
        const response = await fetch(full_url, { headers });

        if (!response.ok) {
            throw new Error(`Error HTTP! Estado: ${response.status} ${response.statusText}`);
        }

        const result = await response.json();
    
        const data = result.data;
        const ip_score = data.abuseConfidenceScore;

        await log(`Checking IP ${ip}`); 
        await log(`Confidence score is ${ip_score}`);

        // Si puntaje de sospecha es >= 50, entonces produce resultado verdadero
        if (ip_score >= 50) {
            await log(`IP ${ip} is suspicious`);
            
            return true;
        }
        
        return false;

    } catch (error) {
        await log(`Error checking IP: ${error.message}`, "ERROR");
        return false; // Se asume falso si hay error en la API
    }
}


async function main() {

    // Ejecutar comando /usr/sbin/psad -S | grep -oP '^SRC:\s+\K[\d\.]+' > /opt/autoblock-ip/psad-ip-list.txt
    //   y almacenar su output en archivo de texto psad-ip-list.txt
    await usePSADAndOverwriteTextFile();

    // Crear sets basados en el contenido de los archivos de texto
    // Se lee el archivo donde el comando /usr/sbin/psad guarda la lista.
    const psad_ip_list = await loadIPSet(PSAD_OUTPUT_PATH); 
    const whitelist = await loadIPSet(WHITELIST_FILE);
    const blacklist = await loadIPSet(BLACKLIST_FILE);
    const temp_ignore_list = await loadIPSet(TEMP_IGNORE_LIST_FILE);

    await log(`Total IPs de psad a chequear: ${psad_ip_list.size}`);
    
    // Por cada ip en la lista de IP totales, filtrar eliminando IP en whitelist y blacklist,
    //   luego chequear puntaje de sospecha con API de AbuseIPDB, y si es sospechosa, entonces bloquear IP (con ufw).
    for (const ip of psad_ip_list) {

        if (whitelist.has(ip)) {
            await log(`Skipping whitelisted IP ${ip}`);
            continue;
        }

        if (blacklist.has(ip)) {
            //print(f"Already blocked: {ip}")
            continue;
        }

        if (temp_ignore_list.has(ip)) {
            continue;
        }
        
        // Si IP es sospechosa, bloquear con ufw y agregar a blacklist.txt; si NO, agregar a temp-ignore-list.txt
        if (await isSuspiciousIP(ip)) {
            await blockIP(ip);
            await saveIPToBlacklist(ip);
        } 
        else {
            await saveIPToTempIgnoreList(ip);
            await log(`${ip} is not suspicious (confidence score < 50)`);
        }
    }
    
    await log(`--- Proceso Finalizado ---`, "ÉXITO");
}


// SACADA DE IA. Función helper para registrar información en archivo .log correspondiente, y 
//   además mostrar en consola
async function log(message, level = 'INFO') {
    
    const entry = `[${new Date().toISOString().slice(0, 16)}] [${level}] ${message}\n`;       // Formato de timestamp "2025-12-08T04:33"
    
    fs.appendFile(LOG_FILE, entry);
    
    console.log(entry.trim());            // También mostrar en consola
}


// Ejecutar la función principal
main();
