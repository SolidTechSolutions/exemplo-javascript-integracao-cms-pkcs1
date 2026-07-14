'use strict';

/**
 * [EN]    Service for two-step CAdES (CMS) signing using PKCS#1 (external private key).
 *         The private key never leaves the client device; only the public certificate PEM is sent.
 *
 *         Flow:
 *           1. prepareSignature — sends documents + certificate; receives hashes + finalNonce.
 *           2. finalizeSignature — sends finalNonce + signed hashes; receives signing result.
 *
 * [PT-BR] Serviço para assinatura CAdES (CMS) em dois passos com PKCS#1 (chave privada externa).
 *         A chave privada nunca sai do dispositivo do cliente; apenas o PEM do certificado é enviado.
 *
 *         Fluxo:
 *           1. prepareSignature — envia documentos + certificado; recebe hashes + finalNonce.
 *           2. finalizeSignature — envia finalNonce + hashes assinados; recebe resultado da assinatura.
 */

const axios = require('axios');
const FormData = require('form-data');

class CmsPkcs1Service {
  constructor() {
    this.baseUrl = (process.env.SOLIDSIGN_API_BASE_URL || '').replace(/\/$/, '');
    this.authorization = process.env.SOLIDSIGN_API_AUTHORIZATION || '';
    this.profile = process.env.SOLIDSIGN_SIG_PROFILE || 'ADRB';
    this.hashAlgorithm = process.env.SOLIDSIGN_SIG_HASH_ALGORITHM || 'SHA256';
    this.signaturePackaging = process.env.SOLIDSIGN_SIG_PACKAGING || 'ENVELOPING';
    this.signerCertPem = process.env.SOLIDSIGN_CERT_PEM || '';
  }

  async prepareSignature(documents) {
    console.info(`CMS PKCS1 prepare for ${documents.length} document(s).`);
    const prepUrl = `${this.baseUrl}/solidsign/dsig/cms/pkcs1/sign-preparation`;
    const form = new FormData();

    for (let i = 0; i < documents.length; i++) {
      form.append(`document[${i}]`, documents[i].buffer, { filename: documents[i].originalname });
    }

    form.append('profile', this.profile);
    form.append('hashAlgorithm', this.hashAlgorithm);
    form.append('signaturePackaging', this.signaturePackaging);
    form.append('certificate', this.signerCertPem);

    try {
      const resp = await axios.post(prepUrl, form, {
        headers: { Authorization: this.authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      console.info(`CMS PKCS1 preparation OK. finalNonce=${resp.data.finalNonce}`);
      return resp.data;
    } catch (err) {
      this._logError('CMS PKCS1 preparation', err);
      return null;
    }
  }

  async finalizeSignature(allParams) {
    console.info('CMS PKCS1 finalize.');
    const finalUrl = `${this.baseUrl}/solidsign/dsig/cms/pkcs1/sign-finalization`;
    const form = new FormData();
    for (const [key, value] of Object.entries(allParams)) form.append(key, value);

    try {
      const resp = await axios.post(finalUrl, form, {
        headers: { Authorization: this.authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      console.info(`CMS PKCS1 finalization OK. identifier=${resp.data.identifier}`);
      return resp.data;
    } catch (err) {
      this._logError('CMS PKCS1 finalization', err);
      return null;
    }
  }

  async prepareForm({ authorization, baseUrl, certificate, documents,
    profile, hashAlgorithm, signaturePackaging, policyVersion }) {

    const prepUrl = `${baseUrl.replace(/\/$/, '')}/solidsign/dsig/cms/pkcs1/sign-preparation`;
    const form = new FormData();

    for (let i = 0; i < documents.length; i++) {
      form.append(`document[${i}]`, documents[i].buffer, { filename: documents[i].originalname });
    }

    form.append('certificate', certificate);
    if (profile)            form.append('profile', profile);
    if (hashAlgorithm)      form.append('hashAlgorithm', hashAlgorithm);
    if (signaturePackaging) form.append('signaturePackaging', signaturePackaging);
    if (policyVersion)      form.append('policyVersion', policyVersion);

    try {
      const resp = await axios.post(prepUrl, form, {
        headers: { Authorization: authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      console.info(`CMS PKCS1 form preparation OK. finalNonce=${resp.data.finalNonce}`);
      return resp.data;
    } catch (err) {
      this._logError('CMS PKCS1 form preparation', err);
      return null;
    }
  }

  async finalizeForm(authorization, baseUrl, allParams) {
    const finalUrl = `${baseUrl.replace(/\/$/, '')}/solidsign/dsig/cms/pkcs1/sign-finalization`;
    const form = new FormData();
    for (const [key, value] of Object.entries(allParams)) form.append(key, value);

    try {
      const resp = await axios.post(finalUrl, form, {
        headers: { Authorization: authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      console.info('CMS PKCS1 form finalization OK.');
      return resp.data;
    } catch (err) {
      this._logError('CMS PKCS1 form finalization', err);
      return null;
    }
  }

  _logError(context, err) {
    if (err.response) {
      console.error(`SolidSign API error ${err.response.status} during ${context}: ${JSON.stringify(err.response.data)}`);
    } else {
      console.error(`Unexpected error during ${context}: ${err.message}`);
    }
  }
}

module.exports = CmsPkcs1Service;
