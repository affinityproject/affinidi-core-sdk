import { profile } from '@affinidi/common'
import { CommonNetworkMember as CoreNetwork, __dangerous } from '@affinidi/wallet-core-sdk'
import { EventComponent } from '@affinidi/affinity-metrics-lib'

import { FetchCredentialsPaginationOptions } from '@affinidi/wallet-core-sdk/dist/dto/shared.dto'
import platformEncryptionTools from './PlatformEncryptionTools'

export type SdkOptions = __dangerous.SdkOptions & {
  issueSignupCredential?: boolean
}

const COMPONENT = EventComponent.AffinidiExpoSDK

@profile()
export class AffinityWallet extends CoreNetwork {
  _skipBackupCredentials: boolean = false
  _credentials: any = []

  constructor(
    password: string,
    encryptedSeed: string,
    options: __dangerous.SdkOptions = {},
    component: EventComponent = COMPONENT,
  ) {
    super(password, encryptedSeed, platformEncryptionTools, options, component)

    this.skipBackupCredentials = options.skipBackupCredentials
  }

  set skipBackupCredentials(value: boolean) {
    this._skipBackupCredentials = value
  }

  get skipBackupCredentials() {
    return this._skipBackupCredentials
  }

  get credentials() {
    return this._credentials
  }

  /**
   * @description Logins with access token of Cognito user registered in Affinity
   * @param options - optional parameters for AffinityWallet initialization
   * @returns initialized instance of SDK or throws `COR-9` UnprocessableEntityError,
   * if user is not logged in.
   */
  static async init(options: __dangerous.SdkOptions = {}): Promise<AffinityWallet> {
    await __dangerous.ParametersValidator.validate([
      { isArray: false, type: __dangerous.SdkOptions, isRequired: false, value: options },
    ])

    const { keyStorageUrl, userPoolId } = CoreNetwork.setEnvironmentVarialbles(options)
    const { accessToken } = __dangerous.readUserTokensFromSessionStorage(userPoolId)

    const encryptedSeed = await __dangerous.WalletStorageService.pullEncryptedSeed(accessToken, keyStorageUrl, options)
    const encryptionKey = await __dangerous.WalletStorageService.pullEncryptionKey(accessToken)

    return new AffinityWallet(encryptionKey, encryptedSeed, options)
  }

  static async afterConfirmSignUp(
    affinityWallet: AffinityWallet,
    originalOptions: SdkOptions = { issueSignupCredential: false },
  ): Promise<void> {
    const options = Object.assign({}, affinityWallet._sdkOptions, originalOptions)
    const { idToken } = affinityWallet.cognitoUserTokens

    if (options.issueSignupCredential) {
      const signedCredentials = await affinityWallet.getSignupCredentials(idToken, options)

      if (affinityWallet.skipBackupCredentials) {
        affinityWallet._credentials = signedCredentials
      } else {
        await affinityWallet.saveCredentials(signedCredentials)
      }
    }
  }

  /**
   * @description Creates encrypted message for another user DID
   * 1. resolve DID (for whom message will be encrypted)
   * 2. get public key from resolved DID document
   * 3. encrypt message using public key of resolved DID
   * @param did - DID of user for whom message will be sent (only this user
   * will be able to decrypt it using his private key),
   * or if DID Document is passed, resolveDid won't happen
   * @param object - message object which will be send
   * @returns encryptedMessage - string version of encrypted message
   */
  async createEncryptedMessage(did: string | any, object: any) {
    let didDocument = did

    if (typeof did === 'string') {
      didDocument = await this.resolveDid(did)
    }

    const publicKeyHex = this.getPublicKeyHexFromDidDocument(didDocument)
    const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex')

    return platformEncryptionTools.encryptByPublicKey(publicKeyBuffer, object)
  }

  /**
   * @description Decrypts message using user's private key
   * @param encryptedMessage - message encrypted for you by your public key
   * @returns decrypted message
   */
  async readEncryptedMessage(encryptedMessage: string): Promise<any> {
    const privateKeyBuffer = this._keysService.getOwnPrivateKey()
    return platformEncryptionTools.decryptByPrivateKey(privateKeyBuffer, encryptedMessage)
  }

  /**
   * @description Save's encrypted VCs in Affinity Guardian Wallet
   * 1. encrypt VCs
   * 2. store encrypted VCs in Affinity Guardian Wallet
   * @param data - array of VCs
   * @param storageRegion - (optional) specify AWS region where credentials will be stored
   * @returns array of ids for corelated records
   */
  async saveCredentials(data: any, storageRegion?: string): Promise<any> {
    const result = await this._walletStorageService.saveUnencryptedCredentials(data, storageRegion)

    this._sendVCSavedMetrics(data)
    // NOTE: what if creds actually were not saved in the vault?
    //       follow up with Isaak/Dustin on this - should we parse the response
    //       to define if we need to send the metrics
    return result
  }

  /**
   * @description Retrieve only the credential at given index
   * @param credentialIndex - index for the VC in vault
   * @returns a single VC
   */
  async getCredentialByIndex(credentialIndex: number): Promise<any> {
    const paginationOptions: FetchCredentialsPaginationOptions = { skip: credentialIndex, limit: 1 }
    const credentials = await this._walletStorageService.fetchDecryptedCredentials(paginationOptions)

    if (!credentials[0]) {
      throw new __dangerous.SdkError('COR-14')
    }

    return credentials[0]
  }

  /**
   * @description Searches all of VCs for matches for the given credentialShareRequestToken
   *   or returns all of your offline VCs
   *   or fetches a subset of backup VCs
   * 1. pull encrypted VCs
   * 2. decrypt encrypted VCs
   * 3. optionally filter VCs by type
   * @param credentialShareRequestToken - JWT received from verifier, if given will search in all VCs
   * @param fetchBackupCredentials - optional, if false - returns all credentials from instance ignoring pagination
   * @param paginationOptions - if fetching from backup, optional range for credentials to be pulled (default is skip: 0, limit: 100)
   * @returns array of VCs
   */
  async getCredentials(
    credentialShareRequestToken: string = null,
    fetchBackupCredentials: boolean = true,
  ): Promise<any[]> {
    const credentials = fetchBackupCredentials ? await this.fetchAllCredentials() : this._credentials

    if (credentialShareRequestToken) {
      return this._walletStorageService.filterCredentials(credentialShareRequestToken, credentials)
    }

    return credentials
  }

  private async fetchAllCredentials() {
    const credentials = await this._walletStorageService.fetchAllDecryptedCredentials()
    this._credentials = credentials
    return credentials
  }

  /**
   * @description Delete credential by id if found in given range
   * @param id - id of the credential
   * @param credentialIndex - credential to remove
   */
  async deleteCredential(id: string, credentialIndex?: string): Promise<void> {
    if (credentialIndex !== undefined && id) {
      throw new __dangerous.SdkError('COR-1', {
        errors: [{ message: 'can not pass both id and credentialIndex at the same time' }],
      })
    }

    const index = credentialIndex ?? (await this._walletStorageService.findCredentialIndexById(id))

    return this.deleteCredentialByIndex(index)
  }
}
