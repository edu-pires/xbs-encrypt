import express from 'express';
import { encryptPayload, decryptPayload } from './utils/crypto.js';

const app = express();
app.use(express.json());

app.post('/encrypt', async (req, res) => {
  try {
    const { payload, cert, kid } = req.body;
    const result = await encryptPayload(payload, cert, kid);
    res.json({ encrypted_payload: { data: result } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/decrypt', async (req, res) => {
  try {
    const { jwe, privateKeyPath, password } = req.body;
    const result = await decryptPayload(jwe, privateKeyPath, password);
    res.json(JSON.parse(result));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
