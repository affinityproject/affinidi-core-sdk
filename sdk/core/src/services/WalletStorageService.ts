import { toRpcSig, ecsign } from 'ethereumjs-util'
import { JwtService, KeysService, profile } from '@affinidi/common'
import { BloomVaultApiService, KeyStorageApiService } from '@affinidi/internal-api-clients'
import { DidAuthService } from '@affinidi/affinidi-did-auth-lib'

import { Env, FetchCredentialsPaginationOptions } from '../dto/shared.dto'
import { isW3cCredential } from '../_helpers'

import { IPlatformEncryptionTools } from '../shared/interfaces'
import { STAGING_KEY_STORAGE_URL } from '../_defaultConfig'

import { SignedCredential } from '../dto/shared.dto'
import { ParametersValidator } from '../shared'
import SdkErrorFromCode from '../shared/SdkErrorFromCode'
import AffinidiVaultStorageService from './AffinidiVaultStorageService'

const keccak256 = require('keccak256')
const createHash = require('create-hash')
const secp256k1 = require('secp256k1')
const bip32 = require('bip32')

const jolocomIdentityKey = "m/73'/0'/0'/0" // eslint-disable-line

/* istanbul ignore next */
const hashPersonalMessage = (message: Buffer): Buffer => {
  const prefix = Buffer.from(`\u0019Ethereum Signed Message:\n${message.length.toString()}`, 'utf-8')
  return keccak256(Buffer.concat([prefix, message]))
}

/* istanbul ignore next */
const privateToPublic = (privateKey: Buffer): Buffer => {
  privateKey = Buffer.from(privateKey)
  return secp256k1.publicKeyCreate(privateKey, false).slice(1)
}

/* istanbul ignore next */
const publicToAddress = (publicKey: Buffer): Buffer => {
  publicKey = Buffer.from(publicKey)
  return keccak256(publicKey).slice(-20)
}

const sha256 = (data: unknown) => {
  return createHash('sha256').update(data).digest()
}

type ConstructorOptions = {
  bloomVaultUrl: string
  affinidiVaultUrl: string
  storageRegion: string
  accessApiKey: string
  audienceDid: string
}

@profile()
export default class WalletStorageService {
  private _storageRegion: string
  private _keysService: KeysService
  private _platformEncryptionTools: IPlatformEncryptionTools
  private _bloomVaultApiService
  private _affinidiVaultStorageService: AffinidiVaultStorageService

  constructor(
    didAuthService: DidAuthService,
    keysService: KeysService,
    platformEncryptionTools: IPlatformEncryptionTools,
    options: ConstructorOptions,
  ) {
    this._keysService = keysService
    this._platformEncryptionTools = platformEncryptionTools
    this._bloomVaultApiService = new BloomVaultApiService({
      accessApiKey: options.accessApiKey,
      vaultUrl: options.bloomVaultUrl,
    })
    this._storageRegion = options.storageRegion

    this._affinidiVaultStorageService = new AffinidiVaultStorageService(
      didAuthService,
      keysService,
      platformEncryptionTools,
      {
        vaultUrl: options.affinidiVaultUrl,
        accessApiKey: options.accessApiKey,
        audienceDid: options.audienceDid,
      },
    )
  }

  static hashFromString(data: string): string {
    const buffer = sha256(Buffer.from(data))

    return buffer.toString('hex')
  }

  /* istanbul ignore next: private function */
  private getVaultKeys() {
    const { seed } = this._keysService.decryptSeed()

    const privateKey = bip32.fromSeed(seed).derivePath(jolocomIdentityKey).privateKey
    const privateKeyHex = privateKey.toString('hex')

    const publicKey = privateToPublic(privateKey)
    const addressHex = publicToAddress(publicKey).toString('hex')

    return { addressHex, privateKeyHex }
  }

  /* istanbul ignore next: ethereumjs-util */
  signByVaultKeys(message: string, privateKey: string) {
    const sig = ecsign(hashPersonalMessage(Buffer.from(message)), Buffer.from(privateKey, 'hex'))

    return toRpcSig(sig.v, sig.r, sig.s)
  }

  /* istanbul ignore next: private method */
  private isTypeMatchRequirements(credentialType: string[], requirementType: string[]): boolean {
    return requirementType.every((value: string) => credentialType.includes(value))
  }

  /* istanbul ignore next: there is test with NULL, but that did not count */
  filterCredentials(credentialShareRequestToken: string, credentials: any[]) {
    if (credentialShareRequestToken) {
      const request = JwtService.fromJWT(credentialShareRequestToken)

      const {
        payload: {
          interactionToken: { credentialRequirements },
        },
      } = request

      // prettier-ignore
      const requirementTypes =
        credentialRequirements.map((credentialRequirement: any) => credentialRequirement.type)

      return credentials.filter((credential) => {
        if (isW3cCredential(credential)) {
          for (const requirementType of requirementTypes) {
            const isTypeMatchRequirements = this.isTypeMatchRequirements(credential.type, requirementType)

            if (isTypeMatchRequirements) {
              return credential
            }
          }
        }
      })
    }

    return credentials
  }

  async fetchEncryptedCredentials(fetchCredentialsPaginationOptions?: FetchCredentialsPaginationOptions) {
    await ParametersValidator.validate([
      {
        isArray: false,
        type: FetchCredentialsPaginationOptions,
        isRequired: false,
        value: fetchCredentialsPaginationOptions,
      },
    ])

    const paginationOptions = WalletStorageService._getPaginationOptionsWithDefault(fetchCredentialsPaginationOptions)

    const token = await this._authorizeVcBloomVault()
    const blobs = await this._fetchEncryptedCredentialsWithPagination(paginationOptions, token)
    return blobs ?? []
  }

  public async fetchAllBlobs() {
    const fetch = this._fetchEncryptedCredentialsWithPagination
    type FetchReturnType = ReturnType<typeof fetch>
    type BlobsType = FetchReturnType extends Promise<infer U> ? NonNullable<U> : never

    const blobChunks: BlobsType[] = []
    const paginationOptions = WalletStorageService._getPaginationOptionsWithDefault()

    const token = await this._authorizeVcBloomVault()

    for (;;) {
      try {
        const blobs = await this._fetchEncryptedCredentialsWithPagination(paginationOptions, token)
        paginationOptions.skip += paginationOptions.limit

        if (!blobs) {
          break
        }

        blobChunks.push(blobs)
      } catch (err) {
        if (err.code === 'COR-14') {
          break
        }

        throw err
      }
    }

    return blobChunks.flatMap((blobs) => blobs)
  }

  private async _fetchEncryptedCredentialsWithPagination(paginationOptions: PaginationOptions, accessToken: string) {
    try {
      const { body: blobs } = await this._bloomVaultApiService.getCredentials({
        accessToken,
        storageRegion: this._storageRegion,
        start: paginationOptions.skip,
        end: paginationOptions.skip + paginationOptions.limit - 1,
      })

      if (blobs.length === 0) {
        return undefined
      }

      return blobs.filter((blob) => blob.cyphertext !== null)
    } catch (error) {
      if (error.httpStatusCode === 404) {
        throw new SdkErrorFromCode('COR-14', {}, error)
      } else {
        throw error
      }
    }
  }

  static async getCredentialOffer(
    accessToken: string,
    keyStorageUrl: string,
    options: { env: Env; accessApiKey: string },
  ): Promise<string> {
    keyStorageUrl = keyStorageUrl || STAGING_KEY_STORAGE_URL
    const { accessApiKey, env } = options
    const service = new KeyStorageApiService({ keyStorageUrl, accessApiKey })
    const { body } = await service.getCredentialOffer({ accessToken, env })
    const { offerToken } = body
    return offerToken
  }

  static async getSignedCredentials(
    accessToken: string,
    credentialOfferResponseToken: string,
    options: { keyStorageUrl?: string; issuerUrl?: string; accessApiKey?: string; apiKey?: string } = {},
  ): Promise<SignedCredential[]> {
    const keyStorageUrl = options.keyStorageUrl || STAGING_KEY_STORAGE_URL
    const { issuerUrl, accessApiKey, apiKey } = options
    const service = new KeyStorageApiService({ keyStorageUrl, accessApiKey })
    const { body } = await service.getSignedCredential(accessToken, {
      credentialOfferResponseToken,
      options: { issuerUrl, accessApiKey, apiKey },
    })

    const { signedCredentials } = body

    return signedCredentials as SignedCredential[]
  }

  private static _getPaginationOptionsWithDefault(
    fetchCredentialsPaginationOptions?: FetchCredentialsPaginationOptions,
  ): PaginationOptions {
    const { skip, limit } = fetchCredentialsPaginationOptions || {}

    return {
      skip: skip || 0,
      limit: limit || 100,
    }
  }

  async fetchAllDecryptedCredentials() {
    const privateKeyBuffer = this._keysService.getOwnPrivateKey()
    const allBlobs = await this.fetchAllBlobs()
    const allCredentials = []
    for (const blob of allBlobs) {
      const credential = await this._platformEncryptionTools.decryptByPrivateKey(privateKeyBuffer, blob.cyphertext)
      allCredentials.push(credential)
    }

    return allCredentials
  }

  async fetchDecryptedCredentials(fetchCredentialsPaginationOptions: FetchCredentialsPaginationOptions) {
    const privateKeyBuffer = this._keysService.getOwnPrivateKey()
    const blobs = await this.fetchEncryptedCredentials(fetchCredentialsPaginationOptions)
    const credentials = []
    for (const blob of blobs) {
      const credential = await this._platformEncryptionTools.decryptByPrivateKey(privateKeyBuffer, blob.cyphertext)
      credentials.push(credential)
    }

    return credentials
  }

  private async _authorizeVcBloomVault(region?: string) {
    const storageRegion = region || this._storageRegion

    const { addressHex, privateKeyHex } = this.getVaultKeys()
    const didEth = `did:ethr:0x${addressHex}`

    const {
      body: { token },
    } = await this._bloomVaultApiService.requestAuthToken({
      storageRegion,
      did: didEth,
    })

    const signature = this.signByVaultKeys(token, privateKeyHex)

    await this._bloomVaultApiService.validateAuthToken({
      storageRegion,
      accessToken: token,
      signature,
      did: didEth,
    })

    return token
  }

  private async _findCredentialIndexById(id: string) {
    const privateKeyBuffer = this._keysService.getOwnPrivateKey()
    const allBlobs = await this.fetchAllBlobs()
    for (const blob of allBlobs) {
      const credential = await this._platformEncryptionTools.decryptByPrivateKey(privateKeyBuffer, blob.cyphertext)

      let credentialId = credential.id

      if (!isW3cCredential(credential) && credential.data) {
        credentialId = credential.data.id
      }

      if (credentialId && credentialId === id) {
        return blob.id
      }
    }

    throw new SdkErrorFromCode('COR-23', { id })
  }

  private async _getEncryptedCredentialById(credentialId: string, storageRegion: string) {
    try {
      const encryptedCredential = await this._affinidiVaultStorageService.getEncryptedCredentialById(
        credentialId,
        storageRegion,
      )
      return encryptedCredential.payload
    } catch (error) {
      if (error.code !== 'AVT-2') {
        throw error
      }

      // should be deleted during migration to affinidi-vault Phase #2
      try {
        const bloomToken = await this._authorizeVcBloomVault()
        const credentialIndex = await this._findCredentialIndexById(credentialId)
        const { body } = await this._bloomVaultApiService.getCredentials({
          accessToken: bloomToken,
          start: credentialIndex,
          end: credentialIndex,
          storageRegion,
        })
        if (body?.length > 0) {
          throw error
        }

        return body[0].cyphertext
      } catch (bloomError) {
        throw error
      }
    }
  }

  public async saveCredentials(credentials: SignedCredential[], storageRegion?: string) {
    storageRegion = storageRegion || this._storageRegion

    const responses = await this._affinidiVaultStorageService.saveCredentials(credentials, storageRegion)

    return responses
  }

  public async getAllCredentials(types: string[][], storageRegion?: string) {
    storageRegion = storageRegion || this._storageRegion

    const credentials = await this._affinidiVaultStorageService.getAllCredentials(types, storageRegion)

    // should be deleted during migration to affinidi-vault Phase #2
    const bloomCredentials = await this.fetchAllDecryptedCredentials()
    if (types.length === 0) {
      credentials.push(...bloomCredentials)
      return credentials
    }

    for (const credential of bloomCredentials) {
      const credentialTypes = Array.isArray(credential?.type) ? (credential.type as string[]) : []

      const isFits = types.some((subtypes) => subtypes.every((subtype) => credentialTypes.includes(subtype)))

      if (isFits) {
        credentials.push(credential)
      }
    }

    return credentials
  }

  public async getCredentialById(credentialId: string, storageRegion?: string): Promise<any> {
    storageRegion = storageRegion || this._storageRegion
    const encryptedCredential = await this._getEncryptedCredentialById(credentialId, storageRegion)

    const privateKey = this._keysService.getOwnPrivateKey()
    const credential = await this._platformEncryptionTools.decryptByPrivateKey(privateKey, encryptedCredential)
    return credential
  }

  public async deleteCredentialById(credentialId: string, storageRegion?: string) {
    storageRegion = storageRegion || this._storageRegion

    try {
      await this._affinidiVaultStorageService.deleteCredentialById(credentialId, storageRegion)
    } catch (error) {
      if (error.code !== 'AVT-2') {
        throw error
      }

      // should be deleted during migration to affinidi-vault Phase #2
      try {
        const bloomToken = await this._authorizeVcBloomVault()
        const credentialIndexToDelete = await this._findCredentialIndexById(credentialId)
        await this._bloomVaultApiService.deleteCredentials({
          accessToken: bloomToken,
          storageRegion,
          start: credentialIndexToDelete,
          end: credentialIndexToDelete,
        })
      } catch (bloomError) {
        throw error
      }
    }
  }

  public async deleteAllCredentials(storageRegion?: string): Promise<void> {
    storageRegion = storageRegion || this._storageRegion

    try {
      await this._affinidiVaultStorageService.deleteAllCredentials(storageRegion)
    } catch (error) {
      throw new SdkErrorFromCode('COR-0', {}, error)
    }

    try {
      const accessToken = await this._authorizeVcBloomVault()
      await this._bloomVaultApiService.deleteCredentials({ accessToken, storageRegion, start: 0, end: 99 })
    } catch (error) {
      throw new SdkErrorFromCode('COR-0', {}, error)
    }
  }
}

type PaginationOptions = {
  skip: number
  limit: number
}
