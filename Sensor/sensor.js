'use-strict';

import express from 'express';

import * as paillierBigint from 'paillier-bigint'


const SERVER_BASE_URL  = 'http://localhost:3001';
const TOTAL_SENSORS    = 10;
const AVG_PER_SECOND   = 10;      // media de sensores que envían por segundo
const LOG_EVERY_N      = 10;      // imprime log 1 de cada N envíos

const SENSOR_TYPES = [
  { type: 'light', value: 0,  unit: 'Wh',   min_cons: 100, max_cons: 5000 , zona: 'Parque de las Moscas'},
  { type: 'water',      value: 0, unit: 'L',    min_cons: 1,   max_cons: 500  ,zona: 'Parque de las Moscas'},
  { type: 'humidity',        value: 0, unit: 'dm3',  min_cons: 50,  max_cons: 3000 ,zona: 'El barrio'},
  { type: 'temperature', value: 0, unit: 'C', min_cons: 150, max_cons: 350  ,zona: 'El barrio'},
];

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Devuelve un delay aleatorio con media = avgMs (distribución exponencial)
// La distribución exponencial es la más realista para modelar
// tiempos entre eventos independientes (como sensores reales)
function randomDelay(avgMs) {
  return -Math.log(Math.random()) * avgMs;
}

/* function textToBigInt(text){
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  const hex = [...bytes].map(b => b.toString(16).padStart(2,'0')).join('');
  return BigInt('0x'+hex);
} */
const SENSOR_TYPE_CODES = {
  light:       0b0001,
  water:       0b0010,
  humidity:    0b0011,
  temperature: 0b0100,
};
function buildSensors(total) {
  return Array.from({ length: total }, (_, i) => {
    const def = SENSOR_TYPES[i % SENSOR_TYPES.length];
    return {
      id: `sensor-${String(i + 1).padStart(5, '0')}`,
      ...def,
    };
  });
}

async function fetchPublicKey() {
  const res = await fetch(`${SERVER_BASE_URL}/paillier-public-key`);
  if (!res.ok) throw new Error(`Error al obtener clave pública: ${res.status}`);
  const { n, g } = await res.json();
  return new paillierBigint.PublicKey(BigInt(n), BigInt(g));
}

async function sendReading(publicKey, sensor) {
  const consumption     = randInt(sensor.min_cons, sensor.max_cons);
  const timestamp = Date.now();

  const typeBits    = BigInt(SENSOR_TYPE_CODES[sensor.type]) & 0xFn;
  const tsBits    = (BigInt(timestamp) & 0xFFFFFFFFFFn) << 40n;
  const consumptionBits = BigInt(consumption) & 0xFFFFFFFFFFn;
  const m         = (typeBits << 80n) | tsBits | consumptionBits;

  const ciphertext = publicKey.encrypt(m);

  await fetch(`${SERVER_BASE_URL}/paillier-decrypt`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({
      ciphertext: ciphertext.toString(),
      zone: sensor.zona
    }),
  });

  return sensor.id;
}

// Cada sensor corre su propio bucle infinito e independiente
async function runSensor(publicKey, sensor, avgIntervalMs, logCounter) {
  while (true) {
    // Espera un tiempo aleatorio antes de enviar (media = avgIntervalMs)
    const delay = randomDelay(avgIntervalMs);
    await new Promise(resolve => setTimeout(resolve, delay));

    try {
      const value = await sendReading(publicKey, sensor);

      // Incrementa contador global y loguea cada LOG_EVERY_N envíos
      logCounter.count++;
      if (logCounter.count % LOG_EVERY_N === 0) {
        console.log(
          `[${new Date().toISOString()}] ${sensor.id} | ` +
          `${sensor.type}: ${sensor.consumption} | ` +
          `total enviados: ${logCounter.count}`
        );
      }
    } catch (err) {
      console.error(`ERROR ${sensor.id}: ${err.message}`);
    }
  }
}

async function main() {
  console.log('Obteniendo clave pública del servido.');
  const publicKey = await fetchPublicKey();
  console.log('Clave pública obtenida.\n');

  const sensors = buildSensors(TOTAL_SENSORS);

  // Intervalo medio por sensor para alcanzar AVG_PER_SECOND envíos/segundo globales
  // Si quieres 50 envíos/s con 100 sensores, cada sensor envía cada 100/50 = 2s de media
  const avgIntervalMs = (TOTAL_SENSORS / AVG_PER_SECOND) * 1000;

  console.log(`Arrancando ${TOTAL_SENSORS} sensores independientes`);
  console.log(`Media global : ${AVG_PER_SECOND} envíos/segundo`);
  console.log(`Media por sensor: cada ${(avgIntervalMs / 1000).toFixed(1)}s\n`);

  // Contador compartido entre todos los sensores para el log global
  const logCounter = { count: 0 };

  // Arranca cada sensor en su propio bucle asíncrono independiente
  // No se usa await aquí para que todos corran en paralelo sin bloquearse
  for (const sensor of sensors) {
    runSensor(publicKey, sensor, avgIntervalMs, logCounter);
  }
}

main().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});