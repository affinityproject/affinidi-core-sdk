'use strict'

import nock from 'nock'
import sinon from 'sinon'
import { expect } from 'chai'

import { JwtService, KeysService } from '@affinidi/common'
import { KeyStorageApiService } from '@affinidi/internal-api-clients'
import { DidAuthService } from '@affinidi/affinidi-did-auth-lib'
import { authorizeVault } from './../../helpers'
import KeyManagementService from '../../../src/services/KeyManagementService'
import WalletStorageService from '../../../src/services/WalletStorageService'
import {
  STAGING_AFFINIDI_VAULT_URL,
  STAGING_KEY_STORAGE_URL,
  STAGING_BLOOM_VAULT_URL,
} from '../../../src/_defaultConfig'

import { generateTestDIDs } from '../../factory/didFactory'
import { testPlatformTools } from '../../helpers/testPlatformTools'

import signedCredential from '../../factory/signedCredential'

import credentialShareRequestToken from '../../factory/credentialShareRequestToken'
import parsedCredentialShareRequestToken from '../../factory/parsedCredentialShareRequestToken'
import { SignedCredential } from '../../../src/dto'

let walletPassword: string

let encryptedSeed: string

const fetchCredentialsPath = '/data/0/99'
const fetchCredentialsBase = '/data/'

const createWalletStorageService = () => {
  const keysService = new KeysService(encryptedSeed, walletPassword)
  const didAuthService = new DidAuthService({ encryptedSeed, encryptionKey: walletPassword })
  return new WalletStorageService(didAuthService, keysService, testPlatformTools, {
    bloomVaultUrl: STAGING_BLOOM_VAULT_URL,
    affinidiVaultUrl: STAGING_AFFINIDI_VAULT_URL,
    accessApiKey: undefined,
    storageRegion: undefined,
    audienceDid: '',
  })
}

const createKeyManagementService = () => {
  return new KeyManagementService({
    keyStorageUrl: STAGING_KEY_STORAGE_URL,
    accessApiKey: undefined,
  })
}

describe('WalletStorageService', () => {
  before(async () => {
    const testDids = await generateTestDIDs()
    walletPassword = testDids.password

    encryptedSeed = testDids.jolo.encryptedSeed
  })
  after(() => {
    nock.cleanAll()
  })

  afterEach(() => {
    sinon.restore()
  })

  it('#saveCredentials', async () => {
    await authorizeVault()

    const saveCredentialPath = '/data'

    nock(STAGING_AFFINIDI_VAULT_URL)
      .filteringPath(() => saveCredentialPath)
      .post(saveCredentialPath)
      .reply(200, {})

    const walletStorageService = createWalletStorageService()

    const response = await walletStorageService.saveCredentials([{} as SignedCredential])

    expect(response).to.be.an('array')
  })

  it('#pullEncryptedSeed', async () => {
    const encryptedSeed = 'encryptedSeed'
    const readMyKeyPath = '/api/v1/keys/readMyKey'

    sinon.stub(KeyManagementService.prototype as any, '_pullEncryptionKey')
    nock(STAGING_KEY_STORAGE_URL)
      .filteringPath(() => readMyKeyPath)
      .get(readMyKeyPath)
      .reply(200, { encryptedSeed })

    const keyManagementService = createKeyManagementService()
    const response = await keyManagementService.pullKeyAndSeed('accessToken')

    expect(response.encryptedSeed).to.include(encryptedSeed)
  })

  it('#filterCredentials', () => {
    sinon.stub(JwtService, 'fromJWT').returns(parsedCredentialShareRequestToken)

    const walletStorageService = createWalletStorageService()

    const credentials = [signedCredential]
    const response = walletStorageService.filterCredentials(credentialShareRequestToken, credentials)

    expect(response).to.be.an('array')
    expect(response).to.include(signedCredential)
  })

  it('#filterCredentials when multiple credential requirements and multiple credential intersect', () => {
    const parsedCredentialShareRequestToken = {
      payload: {
        interactionToken: {
          credentialRequirements: [
            {
              type: ['Denis'],
            },
            {
              type: ['Stas', 'Alex'],
            },
          ],
        },
      },
    }

    sinon.stub(JwtService, 'fromJWT').returns(parsedCredentialShareRequestToken)

    const walletStorageService = createWalletStorageService()

    const expectedFilteredCredentialsToReturn = [
      { type: ['Denis', 'Igor', 'Max', 'Artem'] },
      { type: ['Sasha', 'Alex', 'Stas'] },
    ]

    const credentials = [
      { type: ['Alex', 'Sergiy'] },
      { type: ['Stas'] },
      ...expectedFilteredCredentialsToReturn,
      { type: ['Roman'] },
      { type: ['Max', 'Sergiy'] },
    ]

    const response = walletStorageService.filterCredentials(credentialShareRequestToken, credentials)

    expect(response).to.be.an('array')
    expect(response).to.eql(expectedFilteredCredentialsToReturn)
  })

  it('#filterCredentials when share request token not provided', () => {
    sinon.stub(JwtService, 'fromJWT').returns(parsedCredentialShareRequestToken)

    const walletStorageService = createWalletStorageService()

    const credentials = [signedCredential]
    const response = walletStorageService.filterCredentials(null, credentials)

    expect(response).to.be.an('array')
    expect(response).to.include(signedCredential)
  })

  it('#fetchEncryptedCredentials', async () => {
    await authorizeVault()

    nock(STAGING_AFFINIDI_VAULT_URL).get(fetchCredentialsPath).reply(200, [signedCredential])

    const walletStorageService = createWalletStorageService()
    const response = await walletStorageService.fetchEncryptedCredentials()

    expect(response).to.be.an('array')
    expect(response).to.eql([signedCredential])
  })

  it('#fetchEncryptedCredentials throws `COR-14 / 404` when no credentials found', async () => {
    await authorizeVault()

    nock(STAGING_AFFINIDI_VAULT_URL).get(fetchCredentialsPath).reply(404, {})

    const walletStorageService = createWalletStorageService()

    let errorResponse

    try {
      await walletStorageService.fetchEncryptedCredentials()
    } catch (error) {
      errorResponse = error
    }

    const { code, httpStatusCode } = errorResponse

    expect(code).to.eql('COR-14')
    expect(httpStatusCode).to.eql(404)
  })

  it('#fetchEncryptedCredentials throws error returned from vault', async () => {
    await authorizeVault()

    nock(STAGING_AFFINIDI_VAULT_URL).get(fetchCredentialsPath).reply(500, {})

    const walletStorageService = createWalletStorageService()

    let errorResponse

    try {
      await walletStorageService.fetchEncryptedCredentials()
    } catch (error) {
      errorResponse = error
    }

    expect(errorResponse.httpStatusCode).to.eql(500)
  })

  describe('#fetchAllBlobs', () => {
    it('should work for single page', async () => {
      await authorizeVault()

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '0/99')
        .reply(200, [signedCredential])

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '100/199')
        .reply(200, [])

      const walletStorageService = createWalletStorageService()
      const response = await walletStorageService.fetchAllBlobs()
      expect(response).to.be.an('array')
      expect(response).to.eql([signedCredential])
    })

    it('should work for multiple pages', async () => {
      await authorizeVault()

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '0/99')
        .reply(200, Array(100).fill(signedCredential))

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '100/199')
        .reply(200, Array(100).fill(signedCredential))

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '200/299')
        .reply(200, Array(50).fill(signedCredential))

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '300/399')
        .reply(200, [])

      const walletStorageService = createWalletStorageService()
      const response = await walletStorageService.fetchAllBlobs()

      expect(response).to.be.an('array')
      expect(response.length).to.eql(250)
      expect(response).to.eql(Array(250).fill(signedCredential))
    })

    it('should work for whole number of pages', async () => {
      await authorizeVault()

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '0/99')
        .reply(200, Array(100).fill(signedCredential))

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '100/199')
        .reply(200, Array(100).fill(signedCredential))

      nock(STAGING_AFFINIDI_VAULT_URL)
        .get(fetchCredentialsBase + '200/299')
        .reply(200, [])

      const walletStorageService = createWalletStorageService()
      const response = await walletStorageService.fetchAllBlobs()

      expect(response).to.be.an('array')
      expect(response.length).to.eql(200)
      expect(response).to.eql(Array(200).fill(signedCredential))
    })

    it('should handle deleted values when fetching all', async () => {
      await authorizeVault()

      {
        const expectedResult = Array(100).fill(signedCredential)
        expectedResult[2] = { cyphertext: null }
        const expectedPath = `${fetchCredentialsBase}0/99`
        nock(STAGING_AFFINIDI_VAULT_URL).get(expectedPath).reply(200, expectedResult)
      }

      {
        const expectedResult = Array(100).fill(signedCredential)
        expectedResult[90] = { cyphertext: null }
        const expectedPath = `${fetchCredentialsBase}100/199`
        nock(STAGING_AFFINIDI_VAULT_URL).get(expectedPath).reply(200, expectedResult)
      }

      {
        const expectedResult = Array(50).fill(signedCredential)
        expectedResult[30] = { cyphertext: null }
        const expectedPath = `${fetchCredentialsBase}200/299`
        nock(STAGING_AFFINIDI_VAULT_URL).get(expectedPath).reply(200, expectedResult)
      }

      {
        const expectedPath = `${fetchCredentialsBase}300/399`
        nock(STAGING_AFFINIDI_VAULT_URL).get(expectedPath).reply(200, [])
      }

      const walletStorageService = createWalletStorageService()
      const allBlobs = await walletStorageService.fetchAllBlobs()

      expect(allBlobs.length).to.eql(247)
      expect(allBlobs).to.eql(Array(247).fill(signedCredential))
    })
  })

  describe('#fetchEncryptedCredentials works with pagination', async () => {
    const cases = [
      { args: [{}], path: '0/99' },
      { args: [{ limit: 5 }], path: '0/4' },
      { args: [{ skip: 1 }], path: '1/100' },
      { args: [{ skip: 1, limit: 1 }], path: '1/1' },
    ]

    for (const { args, path } of cases) {
      it(`should request correct path with args ${JSON.stringify(args)}`, async () => {
        await authorizeVault()

        const expectedPath = fetchCredentialsBase + path
        nock(STAGING_AFFINIDI_VAULT_URL).get(expectedPath).reply(200, [signedCredential])

        const walletStorageService = createWalletStorageService()
        const response = await walletStorageService.fetchEncryptedCredentials(...args)

        expect(response).to.be.an('array')
        expect(response).to.eql([signedCredential])
      })
    }

    it('should fail with invalid parameters', async () => {
      const walletStorageService = createWalletStorageService()

      let errorResponse

      try {
        await walletStorageService.fetchEncryptedCredentials({ skip: -1, limit: -1 })
      } catch (error) {
        errorResponse = error
      }

      expect(errorResponse).not.to.be.undefined
      expect(errorResponse.code).to.be.eq('COR-1')
    })

    it('should handle deleted values', async () => {
      await authorizeVault()

      const expectedResult = Array(5).fill(signedCredential)
      expectedResult[2] = { cyphertext: null }
      const expectedPath = `${fetchCredentialsBase}0/99`
      nock(STAGING_AFFINIDI_VAULT_URL).get(expectedPath).reply(200, expectedResult)

      const walletStorageService = createWalletStorageService()
      const response = await walletStorageService.fetchEncryptedCredentials()

      expect(response).to.be.an('array')
      expect(response.length).to.eql(4)
    })
  })

  it('#adminConfirmUser', async () => {
    const username = 'username'
    const adminConfirmUserPath = '/api/v1/userManagement/adminConfirmUser'

    nock(STAGING_KEY_STORAGE_URL)
      .filteringPath(() => adminConfirmUserPath)
      .post(adminConfirmUserPath)
      .reply(200, {})

    const keyStorageApiService = new KeyStorageApiService({
      keyStorageUrl: STAGING_KEY_STORAGE_URL,
      accessApiKey: undefined,
    })
    const response = await keyStorageApiService.adminConfirmUser({ username })

    expect(response).to.exist
  })

  it('#getCredentialOffer', async () => {
    const idToken = 'idToken'
    const getCredentialOfferPath = '/api/v1/issuer/getCredentialOffer'

    nock(STAGING_KEY_STORAGE_URL)
      .filteringPath(() => getCredentialOfferPath)
      .get(getCredentialOfferPath)
      .reply(200, { offerToken: 'offerToken' })

    const returnedOffer = await WalletStorageService.getCredentialOffer(idToken, STAGING_KEY_STORAGE_URL, {} as any)

    expect(returnedOffer).to.eq('offerToken')
  })

  it('#getSignedCredentials', async () => {
    const idToken = 'idToken'
    const credentialOfferResponse = 'responseToken'
    const getSignedCredentialsPath = '/api/v1/issuer/getSignedCredentials'

    nock(STAGING_KEY_STORAGE_URL)
      .filteringPath(() => getSignedCredentialsPath)
      .post(getSignedCredentialsPath)
      .reply(200, { signedCredentials: ['signedCredential'] })

    const returnedOffer = await WalletStorageService.getSignedCredentials(idToken, credentialOfferResponse)

    expect(returnedOffer[0]).to.eq('signedCredential')
  })
})
