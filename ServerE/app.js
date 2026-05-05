'use-strict';
import { RsaPublicKey } from 'sciots-rsa';
import express from 'express';

const app = express()
const port = 3000

app.use(express.json())

app.get('/', (req, res) => {
  res.json({ mensaje: 'Super Server Funcionando0000000' })
})

app.post('/api/data', (req, res) => {
  console.log('JSON recibido:', req.body)
  res.json({
    ok: true,
    recibido: req.body
  })
})

app.listen(port, () => {
  console.log(`Servidor en http://localhost:${port}`)
})