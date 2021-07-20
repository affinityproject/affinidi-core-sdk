'use strict'

import nock from 'nock'
import sinon from 'sinon'

import { DidAuthService } from '@affinidi/affinidi-did-auth-lib'
import { KeysService } from '@affinidi/common'

import AffinidiVaultStorageService from '../../../src/services/AffinidiVaultStorageService'
import { generateTestDIDs } from '../../factory/didFactory'
import { testPlatformTools } from '../../helpers/testPlatformTools'
import { STAGING_AFFINIDI_VAULT_URL, STAGING_REGISTRY_URL } from '../../../src/_defaultConfig'
import credential from '../../factory/signedCredential'
import { VaultCredential } from '../../../src/dto/vault.dto'
import { expect } from 'chai'

let encryptionKey: string
let encryptedSeed: string
let audienceDid: string
const region = 'eu-west-2'

const createAffinidiStorageService = () => {
  const keysService = new KeysService(encryptedSeed, encryptionKey)
  const didAuthService = new DidAuthService({ encryptedSeed, encryptionKey })
  return new AffinidiVaultStorageService(didAuthService, keysService, testPlatformTools, {
    audienceDid: audienceDid,
    vaultUrl: STAGING_AFFINIDI_VAULT_URL,
    accessApiKey: undefined,
  })
}

const mockDidAuth = () => {
  nock(STAGING_AFFINIDI_VAULT_URL)
    .post('/api/v1/did-auth/create-did-auth-request')
    .reply(
      200,
      '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJkaWQ6ZWxlbTpFaUNILXh4Y25rZ1p2NlF2anZvX1VYbi04RFVkVU4zRXRCSnhvbEFRYlFyQ2NBIyJ9.PC4hlTYT5oc1rtcE3Ngq1LN35vAQXI0QgC2nzzQ9RKw"',
    )

  nock(STAGING_REGISTRY_URL).post('/api/v1/did-auth/create-did-auth-response').reply(200, {})
}

describe('AffinidiVaultStorageService', () => {
  before(async () => {
    const testDids = await generateTestDIDs()
    encryptionKey = testDids.password
    encryptedSeed = testDids.jolo.encryptedSeed
    audienceDid = testDids.elem.did
  })

  after(() => {
    nock.cleanAll()
  })

  afterEach(() => {
    sinon.restore()
  })

  it('#saveCredentials', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .put('/api/v1/credentials/' + credential.id)
      .reply(200, {
        credentialId: credential.id,
      } as VaultCredential)

    const service = createAffinidiStorageService()
    const credentials = await service.saveCredentials([credential], region)

    expect(credentials[0].credentialId).to.eql(credential.id)
  })

  it('#saveCredentialsWithError', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .put('/api/v1/credentials/' + credential.id)
      .reply(500, { code: 'COM-1', message: 'internal server error' })

    const service = createAffinidiStorageService()
    try {
      await service.saveCredentials([credential], region)
    } catch (error) {
      expect(error.code).to.eql('COM-1')
    }
  })

  it('#getAllCredentials', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .get('/api/v1/credentials')
      .reply(200, {
        credentials: [
          {
            credentialId: credential.id,
            payload: JSON.stringify({ id: credential.id }),
          } as VaultCredential,
        ],
      })

    const service = createAffinidiStorageService()
    const credentials = await service.getAllCredentials([], region)
    expect(credentials[0].credentialId).to.eql(credential.id)
  })

  it('#getAllCredentialsByTypes', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .get('/api/v1/credentials?types=' + JSON.stringify([credential.type]))
      .reply(200, {
        credentials: [
          {
            credentialId: credential.id,
            payload: JSON.stringify({ id: credential.id }),
          } as VaultCredential,
        ],
      })

    const service = createAffinidiStorageService()
    const credentials = await service.getAllCredentials([credential.type], region)
    expect(credentials[0].credentialId).to.eql(credential.id)
  })

  it('#getAllCredentialsWithError', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .get('/api/v1/credentials')
      .reply(500, { code: 'COM-1', message: 'internal server error' })

    const service = createAffinidiStorageService()
    try {
      await service.getAllCredentials([], region)
    } catch (error) {
      expect(error.code).to.eql('COM-1')
    }
  })

  it('#getEncryptedCredentialById', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .get('/api/v1/credentials/' + credential.id)
      .reply(200, {
        credentialId: credential.id,
        payload: JSON.stringify({ id: credential.id }),
      } as VaultCredential)

    const service = createAffinidiStorageService()
    const result = await service.getEncryptedCredentialById(credential.id, region)
    expect(result.credentialId).to.eql(credential.id)
  })

  it('#getEncryptedCredentialByIdWithError', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .get('/api/v1/credentials/' + credential.id)
      .reply(500, { code: 'COM-1', message: 'internal server error' })

    const service = createAffinidiStorageService()
    try {
      await service.getEncryptedCredentialById(credential.id, region)
    } catch (error) {
      expect(error.code).to.eql('COM-1')
    }
  })

  it('#deleteCredentialById', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .delete('/api/v1/credentials/' + credential.id)
      .reply(200, {})

    const service = createAffinidiStorageService()
    await service.deleteCredentialById(credential.id, region)
  })

  it('#deleteCredentialByIdWithError', async () => {
    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL)
      .delete('/api/v1/credentials/' + credential.id)
      .reply(500, { code: 'COM-1', message: 'internal server error' })

    const service = createAffinidiStorageService()
    try {
      await service.deleteCredentialById(credential.id, region)
    } catch (error) {
      expect(error.code).to.eql('COM-1')
    }
  })

  it('#deleteAllCredentials', async () => {
    mockDidAuth()

    const getAllResponse = {
      credentials: [
        {
          credentialId: credential.id,
          payload: JSON.stringify({ id: credential.id }),
        },
        {
          credentialId: credential.id + '1',
          payload: JSON.stringify({ id: credential.id + '1' }),
        },
      ] as VaultCredential[],
    }

    mockDidAuth()

    nock(STAGING_AFFINIDI_VAULT_URL).get('/api/v1/credentials').reply(200, getAllResponse)

    for (const cred of getAllResponse.credentials) {
      nock(STAGING_AFFINIDI_VAULT_URL)
        .delete('/api/v1/credentials/' + cred.credentialId)
        .reply(200, {})
    }

    const service = createAffinidiStorageService()
    await service.deleteAllCredentials(region)
  })
})
