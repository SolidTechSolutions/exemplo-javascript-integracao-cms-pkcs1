'use strict';

/**
 * [EN]    CAdES (CMS) two-step signing example using PKCS#1 (browser extension / external private key).
 *         Start: node src/index.js
 *
 *         Flow:
 *           Step 1 — POST /api/cms/pkcs1/prepare    → returns hashes + finalNonce
 *           Step 2 — POST /api/cms/pkcs1/finalize   → receives signed hashes, returns result
 *
 * [PT-BR] Exemplo de assinatura CAdES (CMS) em dois passos com PKCS#1 (extensão do browser).
 *         Iniciar: node src/index.js
 *
 *         Fluxo:
 *           Passo 1 — POST /api/cms/pkcs1/prepare   → retorna hashes + finalNonce
 *           Passo 2 — POST /api/cms/pkcs1/finalize  → recebe hashes assinados, retorna resultado
 */

require('dotenv').config();
const express = require('express');
const multer = require('multer');
const CmsPkcs1Service = require('./service');

const app = express();
app.use(express.urlencoded({ extended: true }));
const upload = multer({ storage: multer.memoryStorage() });
const service = new CmsPkcs1Service();

app.post('/api/cms/pkcs1/prepare',
  upload.fields([{ name: 'document' }]),
  async (req, res) => {
    const documents = req.files['document'] || [];
    const result = await service.prepareSignature(documents);
    if (result) return res.json(result);
    return res.status(500).json({ error: 'Preparation failed. Check logs.' });
  }
);

app.post('/api/cms/pkcs1/finalize', async (req, res) => {
  const result = await service.finalizeSignature(req.body);
  if (result) return res.json(result);
  return res.status(500).json({ error: 'Finalization failed. Check logs.' });
});

app.post('/api/cms/pkcs1/prepare/form',
  upload.fields([{ name: 'document' }]),
  async (req, res) => {
    const documents = req.files['document'] || [];
    const { authorization, baseUrl, certificate, profile, hashAlgorithm, signaturePackaging, policyVersion } = req.body;

    const result = await service.prepareForm({
      authorization, baseUrl, certificate, documents,
      profile, hashAlgorithm, signaturePackaging, policyVersion,
    });
    if (result) return res.json(result);
    return res.status(500).json({ error: 'Preparation failed. Check logs.' });
  }
);

app.post('/api/cms/pkcs1/finalize/form', async (req, res) => {
  const { authorization, baseUrl, ...rest } = req.body;
  const result = await service.finalizeForm(authorization, baseUrl, rest);
  if (result) return res.json(result);
  return res.status(500).json({ error: 'Finalization failed. Check logs.' });
});

const PORT = process.env.PORT || 8092;
app.listen(PORT, () => console.info(`SolidSign CMS PKCS1 example running on port ${PORT}`));
