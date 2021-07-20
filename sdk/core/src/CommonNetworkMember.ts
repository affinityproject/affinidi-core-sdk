import { profile, DidDocumentService, JwtService, KeysService, MetricsService, Affinity } from '@affinidi/common'
import {
  IssuerApiService,
  RegistryApiService,
  RevocationApiService,
  VerifierApiService,
} from '@affinidi/internal-api-clients'
import { buildVCV1Unsigned, buildVCV1Skeleton, buildVPV1Unsigned } from '@affinidi/vc-common'
import { VCV1, VCV1SubjectBaseMA, VPV1, VCV1Unsigned } from '@affinidi/vc-common'
import { DidAuthService } from '@affinidi/affinidi-did-auth-lib'
import { parse } from 'did-resolver'

import { EventComponent, EventCategory, EventName, EventMetadata } from '@affinidi/affinity-metrics-lib'

import WalletStorageService from './services/WalletStorageService'
import HolderService from './services/HolderService'
import {
  PhoneIssuerService,
  InitiateResponse as PhoneIssuerInitiateResponse,
  VerifyResponse as PhoneIssuerVerifyResponse,
} from './services/PhoneIssuerService'
import {
  EmailIssuerService,
  InitiateResponse as EmailIssuerInitiateResponse,
  VerifyResponse as EmailIssuerVerifyResponse,
} from './services/EmailIssuerService'

import {
  ClaimMetadata,
  SignedCredential,
  SignCredentialOptionalInput,
  OfferedCredential,
  CredentialRequirement,
  JwtOptions,
  SdkOptions,
  CognitoUserTokens,
  MessageParameters,
  KeyParams,
} from './dto/shared.dto'

import { validateUsername } from './shared/validateUsername'

import { FreeFormObject, IPlatformEncryptionTools } from './shared/interfaces'
import { ParametersValidator } from './shared/ParametersValidator'

import {
  CredentialShareResponseOutput,
  CredentialOfferResponseOutput,
  PresentationValidationOutput,
} from './dto/verifier.dto'

import { randomBytes } from './shared/randomBytes'
import { isW3cCredential } from './_helpers'

import { DEFAULT_DID_METHOD, ELEM_DID_METHOD, SUPPORTED_DID_METHODS } from './_defaultConfig'
import { getOptionsFromEnvironment } from './shared/getOptionsFromEnvironment'
import UserManagementService from './services/UserManagementService'
import KeyManagementService from './services/KeyManagementService'
import SdkErrorFromCode from './shared/SdkErrorFromCode'

type GenericConstructor<T, TOptions> = new (
  password: string,
  encryptedSeed: string,
  options: TOptions,
  component?: EventComponent,
) => T
type Constructor<T, TOptions extends SdkOptions> = GenericConstructor<T, TOptions> &
  GenericConstructor<CommonNetworkMember<TOptions>, TOptions>
type AbstractStaticMethods<T, TOptions> = {
  afterConfirmSignUp: (networkMember: T, originalOptions: TOptions) => Promise<void>
}
type ConstructorKeys<T> = {
  [P in keyof T]: T[P] extends new (...args: unknown[]) => unknown ? P : never
}[keyof T]
type OmitConstructor<T> = Omit<T, ConstructorKeys<T>>
type DerivedTypeForOptions<TInstance, TOptions extends SdkOptions> = Constructor<TInstance, TOptions> &
  AbstractStaticMethods<TInstance, TOptions> &
  OmitConstructor<typeof CommonNetworkMember>
type ExtractOptionsType<T extends new (...args: unknown[]) => unknown> = SdkOptions & ConstructorParameters<T>[2]
type DerivedType<T extends DerivedType<T>> = DerivedTypeForOptions<InstanceType<T>, ExtractOptionsType<T>>

/**
 * This class is abstract.
 * You can use implementations from wallet-browser-sdk, wallet-expo-sdk or wallet-react-native-sdk as needed.
 *
 * Alternatively you can implement your own derived class.
 * Derived classes should have:
 *  * A constructor with a signature `new (password: string, encryptedSeed: string, options?: SdkOptions, component?: EventComponent)`
 *  * A static method `afterConfirmSignUp(networkMember: YourClass, originalOptions: SdkOptions) => Promise<void>`
 *
 * Constructor should pass an implementation of `IPlatformEncryptionTools` to the base constructor.
 * This implementation should be compatible with one in other SDKs,
 * it will be used to encrypt and decrypt credentials stored in vault.
 * Alternatively you can provide a stub implementation, with all methods throwing errors,
 * if you are not going to use any features that depend on platform tools.
 *
 * `afterConfirmSignUp` is invoked on every call to `confirmSignUp`, direct or indirect.
 * It allows you to perform some tasks specific to your implementation.
 * You can leave the method body empty if you don't need it.
 */
@profile()
export abstract class CommonNetworkMember<TOptions extends SdkOptions = SdkOptions> {
  private _did: string
  private readonly _encryptedSeed: string
  private _password: string
  protected readonly _walletStorageService: WalletStorageService
  protected readonly _keysService: KeysService
  private readonly _jwtService: JwtService
  private readonly _holderService: HolderService
  private readonly _metricsService: MetricsService
  private readonly _didDocumentService: DidDocumentService
  private readonly _issuerApiService
  private readonly _verifierApiService
  private readonly _registryApiService
  private readonly _revocationApiService
  private readonly _userManagementService
  private readonly _keyManagementService
  protected readonly _affinity: Affinity
  protected readonly _sdkOptions
  private readonly _phoneIssuer: PhoneIssuerService
  private readonly _emailIssuer: EmailIssuerService
  private _didDocumentKeyId: string
  protected readonly _component: EventComponent
  protected cognitoUserTokens: CognitoUserTokens

  constructor(
    password: string,
    encryptedSeed: string,
    platformEncryptionTools: IPlatformEncryptionTools,
    inputOptions: TOptions,
    component: EventComponent,
  ) {
    // await ParametersValidator.validateSync(
    //   [
    //     { isArray: false, type: 'string', isRequired: true, value: password },
    //     { isArray: false, type: 'string', isRequired: true, value: encryptedSeed },
    //     { isArray: false, type: SdkOptions, isRequired: true, value: options }
    //   ]
    // )

    if (!password || !encryptedSeed) {
      // TODO: implement appropriate error wrapper
      throw new Error('`password` and `encryptedSeed` must be provided!')
    }

    if (!platformEncryptionTools?.platformName) {
      throw new Error('`platformEncryptionTools` must be provided!')
    }

    const { accessApiKey, basicOptions, storageRegion, cognitoUserTokens, otherOptions } = getOptionsFromEnvironment(
      inputOptions,
    )

    const {
      issuerUrl,
      keyStorageUrl,
      revocationUrl,
      metricsUrl,
      registryUrl,
      verifierUrl,
      bloomVaultUrl,
      affinidiVaultUrl,
      phoneIssuerBasePath,
      emailIssuerBasePath,
      clientId,
      userPoolId,
    } = basicOptions

    const keysService = new KeysService(encryptedSeed, password)
    this._metricsService = new MetricsService({
      metricsUrl,
      accessApiKey: accessApiKey,
      component: component,
    })
    this._registryApiService = new RegistryApiService({ registryUrl, accessApiKey })
    this._issuerApiService = new IssuerApiService({ issuerUrl, accessApiKey })
    this._verifierApiService = new VerifierApiService({ verifierUrl, accessApiKey })
    this._revocationApiService = new RevocationApiService({ revocationUrl, accessApiKey })
    this._userManagementService = new UserManagementService({ clientId, userPoolId, keyStorageUrl, accessApiKey })
    this._keyManagementService = new KeyManagementService({ keyStorageUrl, accessApiKey })
    this._didDocumentService = new DidDocumentService(keysService)
    const didAuthService = new DidAuthService({ encryptedSeed, encryptionKey: password })
    this._walletStorageService = new WalletStorageService(didAuthService, keysService, platformEncryptionTools, {
      bloomVaultUrl,
      affinidiVaultUrl,
      accessApiKey,
      storageRegion,
      audienceDid: this.did,
    })
    this._jwtService = new JwtService()
    this._holderService = new HolderService({ registryUrl, metricsUrl, accessApiKey }, component)
    this._affinity = new Affinity({
      apiKey: accessApiKey,
      registryUrl: registryUrl,
      metricsUrl: metricsUrl,
      component: component,
    })
    this._phoneIssuer = new PhoneIssuerService({ basePath: phoneIssuerBasePath })
    this._emailIssuer = new EmailIssuerService({ basePath: emailIssuerBasePath })
    this._keysService = keysService

    const sdkOptions = { ...basicOptions, accessApiKey, storageRegion, otherOptions }
    this._sdkOptions = sdkOptions
    this._component = component
    this._encryptedSeed = encryptedSeed
    this._password = password
    this.cognitoUserTokens = cognitoUserTokens
    this._did = null
    this._didDocumentKeyId = null
  }

  /**
   * @deprecated
   */
  protected static setEnvironmentVarialbles(options: SdkOptions) {
    const { accessApiKey, basicOptions, storageRegion, otherOptions } = getOptionsFromEnvironment(options)
    return { ...basicOptions, accessApiKey, storageRegion, otherOptions }
  }

  /**
   * @description Returns user's encrypted seed
   * @returns encrypted seed
   */
  get encryptedSeed(): string {
    return this._encryptedSeed
  }

  /**
   * @description Returns user's accessToken
   * @returns encrypted seed
   */
  get accessToken(): string {
    return this.cognitoUserTokens.accessToken
  }

  /**
   * @description Returns user's password
   * @returns encrypted seed
   */
  get password(): string {
    return this._password
  }

  private static _createUserManagementService = (options: SdkOptions) => {
    const { basicOptions, accessApiKey } = getOptionsFromEnvironment(options)
    return new UserManagementService({ ...basicOptions, accessApiKey })
  }

  private static _createKeyManagementService = (options: SdkOptions) => {
    const { basicOptions, accessApiKey } = getOptionsFromEnvironment(options)
    return new KeyManagementService({ ...basicOptions, accessApiKey })
  }

  /**
   * @description Checks if registration for the user was completed
   * @param username - a valid email, phone number or arbitrary username
   * @param options - object with environment, staging is default { env: 'staging' }
   * @returns `true` if user is uncofirmed in Cognito, and `false` otherwise.
   */
  static async isUserUnconfirmed(username: string, options: SdkOptions) {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: username },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    return userManagementService.doesUnconfirmedUserExist(username)
  }

  /**
   * @description Initilizes instance of SDK from seed
   * @param seedHexWithMethod - seed for derive keys in string hex format
   * @param options - optional parameter { registryUrl: 'https://affinity-registry.dev.affinity-project.org' }
   * @param password - optional password, will be generated, if not provided
   * @returns initialized instance of SDK
   */
  static async fromSeed<T extends DerivedType<T>>(
    this: T,
    seedHexWithMethod: string,
    options: ExtractOptionsType<T>,
    password: string = null,
  ): Promise<InstanceType<T>> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: seedHexWithMethod },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: 'string', isRequired: false, value: password },
    ])

    let passwordBuffer

    if (password) {
      passwordBuffer = KeysService.normalizePassword(password)
    } else {
      passwordBuffer = await randomBytes(32)
      password = passwordBuffer.toString('hex')
    }

    const encryptedSeedWithInitializationVector = await KeysService.encryptSeed(seedHexWithMethod, passwordBuffer)

    return new this(password, encryptedSeedWithInitializationVector, options)
  }

  /**
   * @description Parses JWT and returns DID
   * @param jwt
   * @returns DID of entity who signed JWT
   */
  static getDidFromToken(jwt: string) {
    // await ParametersValidator.validateSync(
    //   [
    //     { isArray: false, type: 'jwt', isRequired: true, value: jwt }
    //   ]
    // )

    return JwtService.getDidFromToken(jwt)
  }

  /**
   * @description Returns hex of public key from DID document
   * @param didDocument - user's DID document
   * @returns public key hex
   */
  getPublicKeyHexFromDidDocument(didDocument: any) {
    // await ParametersValidator.validateSync(
    //   [
    //     { isArray: false, type: 'object', isRequired: true, value: didDocument }
    //   ]
    // )
    // TODO: review: in general case - need to find section at didDocument.publicKey where id === keyId
    const { publicKeyHex } = didDocument.publicKey[0]

    return publicKeyHex
  }

  /**
   * @description Creates DID and anchors it
   * 1. generate seed/keys
   * 2. build DID document
   * 3. sign DID document
   * 4. store DID document in IPFS
   * 5. anchor DID with DID document ID from IPFS
   * @param password - encryption key which will be used to encrypt randomly created seed/keys pair
   * @param options - optional parameter { registryUrl: 'https://affinity-registry.dev.affinity-project.org' }
   * @returns
   *
   * did - hash from public key (your decentralized ID)
   *
   * encryptedSeed - seed is encrypted by provided password. Seed - it's a source to derive your keys
   */
  static async register<T extends DerivedType<T>>(
    this: T,
    password: string,
    options: ExtractOptionsType<T>,
  ): Promise<{ did: string; encryptedSeed: string }> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: password },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const didMethod = options.didMethod || DEFAULT_DID_METHOD
    const seed = await CommonNetworkMember.generateSeed(didMethod)
    const seedHex = seed.toString('hex')
    const seedWithMethod = `${seedHex}++${didMethod}`
    const passwordBuffer = KeysService.normalizePassword(password)
    const encryptedSeed = await KeysService.encryptSeed(seedWithMethod, passwordBuffer)
    const keysService = new KeysService(encryptedSeed, password)

    const didDocumentService = new DidDocumentService(keysService)
    const didDocument = await didDocumentService.buildDidDocument()
    const did = didDocument.id

    await CommonNetworkMember.anchorDid(encryptedSeed, password, didDocument, 0, options)

    return { did, encryptedSeed }
  }

  static async anchorDid(
    encryptedSeed: string,
    password: string,
    didDocument: any,
    nonce: number,
    options: SdkOptions,
  ) {
    const {
      basicOptions: { registryUrl },
      accessApiKey,
    } = getOptionsFromEnvironment(options)

    const api = new RegistryApiService({ registryUrl, accessApiKey })

    const did = didDocument.id

    const keysService = new KeysService(encryptedSeed, password)
    const { seed, didMethod } = keysService.decryptSeed()
    const seedHex = seed.toString('hex')

    /* istanbul ignore next: seems options is {} if not passed to the method */
    if (didMethod !== ELEM_DID_METHOD) {
      const signedDidDocument = await keysService.signDidDocument(didDocument)

      const { body: bodyDidDocument } = await api.putDocumentInIpfs({ document: signedDidDocument })
      const didDocumentAddress = bodyDidDocument.hash

      const {
        body: { digestHex },
      } = await api.createAnchorTransaction({ nonce, did, didDocumentAddress })

      let transactionSignatureJson = ''
      if (digestHex && digestHex !== '') {
        transactionSignatureJson = await keysService.createTransactionSignature(digestHex, seedHex)
      }

      const transactionPublicKey = KeysService.getAnchorTransactionPublicKey(seedHex, didMethod)
      const ethereumPublicKeyHex = transactionPublicKey.toString('hex')

      await api.anchorDid({ did, didDocumentAddress, ethereumPublicKeyHex, transactionSignatureJson, nonce })
    }

    // NOTE: for metrics purpose in case of ELEM method
    if (didMethod === ELEM_DID_METHOD) {
      try {
        await api.anchorDid({ did, didDocumentAddress: '', ethereumPublicKeyHex: '', transactionSignatureJson: '' })
      } catch (error) {
        console.log('to check logs at the backend', error)
      }
    }
  }

  /**
   * @description Resolves DID
   * @param did - decentralized ID
   * @returns DID document
   */
  async resolveDid(did: string) {
    await ParametersValidator.validate([{ isArray: false, type: 'did', isRequired: true, value: did }])

    const { body } = await this._registryApiService.resolveDid({ did })
    const { didDocument } = body

    return didDocument
  }

  /**
   * @description Update DidDocument , supporting only jolo method at this point
   * @param didDocument - updated did document
   * @returns void
   */
  async updateDidDocument(didDocument: any) {
    // TODO: validate didDocument structure
    await ParametersValidator.validate([{ isArray: false, type: 'object', isRequired: true, value: didDocument }])

    const did = didDocument.id
    const isJoloMethod = did.startsWith('did:jolo')
    if (!isJoloMethod) {
      throw new SdkErrorFromCode('COR-20', { did })
    }

    const instanceDid = this.did
    if (instanceDid !== did) {
      throw new SdkErrorFromCode('COR-21', { did, instanceDid })
    }

    const keysService = new KeysService(this._encryptedSeed, this._password)
    const { seed, didMethod } = keysService.decryptSeed()
    const seedHex = seed.toString('hex')
    const transactionPublicKey = KeysService.getAnchorTransactionPublicKey(seedHex, didMethod)
    const ethereumPublicKeyHex = transactionPublicKey.toString('hex')

    const {
      body: { transactionCount },
    } = await this._registryApiService.transactionCount({ ethereumPublicKeyHex })

    const nonce = transactionCount

    await CommonNetworkMember.anchorDid(this._encryptedSeed, this._password, didDocument, nonce, this._sdkOptions)
  }

  /**
   * @description Pulls encrypted seed from Affinity Guardian Wallet
   * 1. get AWS cognito access token
   * 2. using access token pull encrypted seed from Affinity Guardian Wallet
   * associated with this AWS Cognito userId
   * @param username - email or phone number used to create Affinity user
   * @param password - password used on create Affinity user
   */
  async pullEncryptedSeed(username: string, password: string): Promise<string> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: username },
      { isArray: false, type: 'string', isRequired: true, value: password },
    ])

    const { accessToken } = await this._userManagementService.logInWithPassword(username, password)
    const { encryptedSeed } = await this._keyManagementService.pullKeyAndSeed(accessToken)

    return encryptedSeed
  }

  /**
   * @description Saves encrypted seed to Guardian Wallet
   * @param username - email/phoneNumber, registered in Cognito
   * @param password - password for Cognito user
   * @param token - Cognito access token, required for authorization.
   * If not provided, in order to get it, sign in to Cognito will be initiated.
   */
  async storeEncryptedSeed(username: string, password: string, token: string = undefined): Promise<void> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: username },
      { isArray: false, type: 'string', isRequired: true, value: password },
      { isArray: false, type: 'jwt', isRequired: false, value: token },
    ])

    let accessToken = token

    /* istanbul ignore else: code simplicity */
    if (!token) {
      this.cognitoUserTokens = await this._userManagementService.logInWithPassword(username, password)

      accessToken = this.cognitoUserTokens.accessToken
    }

    const { seedHexWithMethod } = this._keysService.decryptSeed()
    await this._keyManagementService.pullEncryptionKeyAndStoreEncryptedSeed(accessToken, seedHexWithMethod)
  }

  /**
   * @description Initiates passwordless login to Affinity
   * @param username - email/phoneNumber, registered in Cognito
   * @param options - optional parameters with specified environment
   * @param messageParameters - optional parameters with specified welcome message
   * @returns token
   */
  static async passwordlessLogin(
    login: string,
    options: SdkOptions,
    messageParameters?: MessageParameters,
  ): Promise<string> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: login },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: MessageParameters, isRequired: false, value: messageParameters },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    return await userManagementService.initiateLogInPasswordless(login, messageParameters)
  }

  /**
   * @description Completes login
   * @param token - received from #passwordlessLogin method
   * @param confirmationCode - OTP sent by AWS Cognito/SES
   * @param options - optional parameters for CommonNetworkMember initialization
   * @returns initialized instance of SDK
   */
  static async completeLoginChallenge<T extends DerivedType<T>>(
    this: T,
    token: string,
    confirmationCode: string,
    inputOptions: ExtractOptionsType<T>,
  ): Promise<InstanceType<T>> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: token },
      { isArray: false, type: 'confirmationCode', isRequired: true, value: confirmationCode },
      { isArray: false, type: SdkOptions, isRequired: true, value: inputOptions },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(inputOptions)
    const keyManagementService = CommonNetworkMember._createKeyManagementService(inputOptions)
    const cognitoUserTokens = await userManagementService.completeLogInPasswordless(token, confirmationCode)
    const { accessToken } = cognitoUserTokens
    const { encryptedSeed, encryptionKey } = await keyManagementService.pullKeyAndSeed(accessToken)

    return new this(encryptionKey, encryptedSeed, {
      ...inputOptions,
      cognitoUserTokens,
    })
  }

  getShareCredential(credentialShareRequestToken: string, options: FreeFormObject): SignedCredential[] {
    const { credentials } = options
    const credentialShareRequest = CommonNetworkMember.fromJWT(credentialShareRequestToken)
    const types = this.getCredentialTypes(credentialShareRequest)

    const filteredCredentials = credentials.filter((cred: SignedCredential) => {
      return types.includes(cred.type[1])
    })

    return filteredCredentials
  }

  /**
   * @description Retrieves a VC based on signup information
   * @param idToken - idToken received from cognito
   * @returns an object with a flag, identifying whether new account was created, and initialized instance of SDK
   */
  async getSignupCredentials(idToken: string, options: SdkOptions): Promise<SignedCredential[]> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: idToken },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const {
      basicOptions: { env, keyStorageUrl },
      accessApiKey,
    } = getOptionsFromEnvironment(options)

    const credentialOfferToken = await WalletStorageService.getCredentialOffer(idToken, keyStorageUrl, {
      env,
      accessApiKey,
    })

    const credentialOfferResponseToken = await this.createCredentialOfferResponseToken(credentialOfferToken)

    return WalletStorageService.getSignedCredentials(idToken, credentialOfferResponseToken, {
      ...options,
      keyStorageUrl,
    })
  }

  /**
   * @description Signs out current user
   */
  async signOut(options: SdkOptions): Promise<void> {
    await ParametersValidator.validate([{ isArray: false, type: SdkOptions, isRequired: true, value: options }])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    const newTokens = await userManagementService.logOut(this.cognitoUserTokens)
    this.cognitoUserTokens = newTokens
  }

  /**
   * @description Initiates reset password flow
   * @param username - email/phoneNumber, registered in Cognito
   * @param options - optional parameters with specified environment
   * @param messageParameters - optional parameters with specified welcome message
   */
  static async forgotPassword(
    login: string,
    options: SdkOptions,
    messageParameters?: MessageParameters,
  ): Promise<void> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: login },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    await userManagementService.initiateForgotPassword(login, messageParameters)
  }

  /**
   * @description Completes reset password flow
   * @param username - email/phoneNumber, registered in Cognito
   * @param confirmationCode - OTP sent by AWS Cognito/SES
   * @param newPassword - new password
   * @param options - optional parameters with specified environment
   */
  static async forgotPasswordSubmit(
    login: string,
    confirmationCode: string,
    newPassword: string,
    options: SdkOptions,
  ): Promise<void> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: login },
      { isArray: false, type: 'confirmationCode', isRequired: true, value: confirmationCode },
      { isArray: false, type: 'string', isRequired: true, value: newPassword },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const userManagementService = this._createUserManagementService(options)
    await userManagementService.completeForgotPassword(login, confirmationCode, newPassword)
  }

  /**
   * @description Logins to Affinity with login and password
   * @param username - email/phoneNumber, registered in Cognito
   * @param password - password for Cognito user
   * @param options - optional parameters for CommonNetworkMember initialization
   * @returns initialized instance of SDK
   */
  static async fromLoginAndPassword<T extends DerivedType<T>>(
    this: T,
    username: string,
    password: string,
    inputOptions: ExtractOptionsType<T>,
  ): Promise<InstanceType<T>> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: username },
      { isArray: false, type: 'password', isRequired: true, value: password },
      { isArray: false, type: SdkOptions, isRequired: true, value: inputOptions },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(inputOptions)
    const keyManagementService = CommonNetworkMember._createKeyManagementService(inputOptions)
    const cognitoUserTokens = await userManagementService.logInWithPassword(username, password)
    const { accessToken } = cognitoUserTokens
    const { encryptedSeed, encryptionKey } = await keyManagementService.pullKeyAndSeed(accessToken)
    return new this(encryptionKey, encryptedSeed, { ...inputOptions, cognitoUserTokens })
  }

  private static _validateKeys(keyParams: KeyParams) {
    const { encryptedSeed, password } = keyParams

    let didMethod
    try {
      const keysService = new KeysService(encryptedSeed, password)
      didMethod = keysService.decryptSeed().didMethod
    } catch (error) {
      throw new SdkErrorFromCode('COR-24', {}, error)
    }

    if (!SUPPORTED_DID_METHODS.includes(didMethod)) {
      const supportedDidMethods = SUPPORTED_DID_METHODS.join(', ')
      throw new SdkErrorFromCode('COR-25', { didMethod, supportedDidMethods })
    }
  }

  /**
   * @description Initiates sign up flow to Affinity wallet with already created did
   * @param keyParams - { ecnryptedSeed, password } - previously created keys to be storead at wallet.
   * @param username - arbitrary username, email or phoneNumber
   * @param password - is required if arbitrary username was provided.
   * It is optional and random one will be generated, if not provided when
   * email or phoneNumber was given as a username.
   * @param options - optional parameters with specified environment
   * @param messageParameters - optional parameters with specified welcome message
   * @returns token or, in case when arbitrary username was used, it returns
   * initialized instance of SDK
   */
  static async signUpWithExistsEntity<T extends DerivedType<T>>(
    this: T,
    keyParams: KeyParams,
    login: string,
    password: string,
    options: ExtractOptionsType<T>,
    messageParameters?: MessageParameters,
  ): Promise<string | InstanceType<T>> {
    const { isUsername } = validateUsername(login)

    if (!isUsername) {
      return CommonNetworkMember._signUpByEmailOrPhone(login, password, options, messageParameters)
    }

    const username = login
    await ParametersValidator.validate([
      { isArray: false, type: KeyParams, isRequired: true, value: keyParams },
      { isArray: false, type: 'string', isRequired: true, value: username },
      { isArray: false, type: 'password', isRequired: true, value: password },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: MessageParameters, isRequired: false, value: messageParameters },
    ])

    CommonNetworkMember._validateKeys(keyParams)

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    const cognitoTokens = await userManagementService.signUpWithUsernameAndConfirm(
      username,
      password,
      messageParameters,
    )
    return CommonNetworkMember._confirmSignUp(this, cognitoTokens, password, keyParams, options)
  }

  private static async _signUpByUsernameAutoConfirm<T extends DerivedType<T>>(
    self: T,
    username: string,
    password: string,
    options: ExtractOptionsType<T>,
    messageParameters?: MessageParameters,
  ): Promise<InstanceType<T>> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: username },
      { isArray: false, type: 'password', isRequired: true, value: password },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: MessageParameters, isRequired: false, value: messageParameters },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    const cognitoTokens = await userManagementService.signUpWithUsernameAndConfirm(
      username,
      password,
      messageParameters,
    )
    const result = await CommonNetworkMember._confirmSignUp(self, cognitoTokens, password, undefined, options)
    await self.afterConfirmSignUp(result, options)
    return result
  }

  private static async _signUpByEmailOrPhone<T extends DerivedType<T>>(
    login: string,
    password: string,
    options: ExtractOptionsType<T>,
    messageParameters?: MessageParameters,
  ): Promise<string> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: login },
      { isArray: false, type: 'password', isRequired: false, value: password },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: MessageParameters, isRequired: false, value: messageParameters },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    return userManagementService.initiateSignUpWithEmailOrPhone(login, password, messageParameters)
  }

  /**
   * @description Initiates sign up flow
   * @param username - arbitrary username, email or phoneNumber
   * @param password - is required if arbitrary username was provided.
   * It is optional and random one will be generated, if not provided when
   * email or phoneNumber was given as a username.
   * @param options - optional parameters with specified environment
   * @param messageParameters - optional parameters with specified welcome message
   * @returns token or, in case when arbitrary username was used, it returns
   * initialized instance of SDK
   */
  static async signUp<T extends DerivedType<T>>(
    this: T,
    login: string,
    password: string,
    options: ExtractOptionsType<T>,
    messageParameters?: MessageParameters,
  ): Promise<string | InstanceType<T>> {
    const { isUsername } = validateUsername(login)

    if (!isUsername) {
      return CommonNetworkMember._signUpByEmailOrPhone(login, password, options, messageParameters)
    }

    return CommonNetworkMember._signUpByUsernameAutoConfirm(this, login, password, options, messageParameters)
  }

  /**
   * @description Completes sign up flow with already created did
   *       (as result created keys will be stored at the Affinity Wallet)
   * NOTE: no need calling this method in case of arbitrary username was given,
   *       as registration is already completed
   * NOTE: This method will throw an error if called for arbitrary username
   * @param keyParams - { ecnryptedSeed, password } - previously created keys to be storead at wallet.
   * @param token - Token returned by signUpWithExistsEntity method.
   * @param confirmationCode - OTP sent by AWS Cognito/SES.
   * @param options - optional parameters for CommonNetworkMember initialization
   * @returns initialized instance of SDK
   */
  static async confirmSignUpWithExistsEntity<T extends DerivedType<T>>(
    this: T,
    keyParams: KeyParams,
    signUpToken: string,
    confirmationCode: string,
    options: ExtractOptionsType<T>,
  ): Promise<InstanceType<T>> {
    ParametersValidator.validate([
      { isArray: false, type: KeyParams, isRequired: true, value: keyParams },
      { isArray: false, type: 'string', isRequired: true, value: signUpToken },
      { isArray: false, type: 'confirmationCode', isRequired: true, value: confirmationCode },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    const { cognitoTokens, shortPassword } = await userManagementService.completeSignUpForEmailOrPhone(
      signUpToken,
      confirmationCode,
    )
    return CommonNetworkMember._confirmSignUp(this, cognitoTokens, shortPassword, keyParams, options)
  }

  private static async _confirmSignUp<T extends DerivedType<T>>(
    self: T,
    cognitoTokens: CognitoUserTokens,
    shortPassword: string,
    keyParams: KeyParams,
    inputOptions: ExtractOptionsType<T>,
  ): Promise<InstanceType<T>> {
    const { accessToken } = cognitoTokens

    if (!keyParams?.encryptedSeed) {
      const passwordHash = WalletStorageService.hashFromString(shortPassword)
      const registerResult = await self.register(passwordHash, inputOptions)
      const encryptedSeed = registerResult.encryptedSeed
      keyParams = { password: passwordHash, encryptedSeed }
    }

    const keyManagementService = this._createKeyManagementService(inputOptions)
    const { encryptionKey, updatedEncryptedSeed } = await keyManagementService.reencryptSeed(
      accessToken,
      keyParams,
      !inputOptions.skipBackupEncryptedSeed,
    )

    return new self(encryptionKey, updatedEncryptedSeed, {
      ...inputOptions,
      cognitoUserTokens: cognitoTokens,
    })
  }

  /**
   * @description Completes sign up flow
   * NOTE: no need calling this method in case of arbitrary username was given,
   *       as registration is already completed.
   * NOTE: this method will throw an error if called for arbitrary username
   * @param confirmationCode - OTP sent by AWS Cognito/SES.
   * @param options - optional parameters for CommonNetworkMember initialization
   * @returns initialized instance of SDK
   */
  static async confirmSignUp<T extends DerivedType<T>>(
    this: T,
    signUpToken: string,
    confirmationCode: string,
    options: ExtractOptionsType<T>,
  ): Promise<InstanceType<T>> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: signUpToken },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: 'confirmationCode', isRequired: true, value: confirmationCode },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    const { cognitoTokens, shortPassword } = await userManagementService.completeSignUpForEmailOrPhone(
      signUpToken,
      confirmationCode,
    )
    const result = await CommonNetworkMember._confirmSignUp(this, cognitoTokens, shortPassword, undefined, options)
    await this.afterConfirmSignUp(result, options)
    return result
  }

  /**
   * @description Resends OTP for sign up flow
   * @param username - email/phoneNumber, registered and unconfirmed in Cognito
   * @param options - optional parameters with specified environment
   * @param messageParameters - optional parameters with specified welcome message
   */
  static async resendSignUpConfirmationCode(
    login: string,
    options: SdkOptions,
    messageParameters?: MessageParameters,
  ): Promise<void> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: login },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: MessageParameters, isRequired: false, value: messageParameters },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    await userManagementService.resendSignUp(login, messageParameters)
  }

  /**
   * @description Initiates passwordless sign in of an existing user,
   * or signs up a new one, if user was not registered
   * @param username - email/phoneNumber, registered in Cognito
   * @param options - optional parameters with specified environment
   * @param messageParameters - optional parameters with specified welcome message
   * @returns token
   */
  static async signIn<T extends DerivedType<T>>(
    this: T,
    login: string,
    options: ExtractOptionsType<T>,
    messageParameters?: MessageParameters,
  ): Promise<string> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: login },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: MessageParameters, isRequired: false, value: messageParameters },
    ])

    // NOTE: This is a passwordless login/sign up flow,
    //       case when user signs up more often
    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    const doesConfirmedUserExist = await userManagementService.doesConfirmedUserExist(login)
    if (doesConfirmedUserExist) {
      return userManagementService.initiateLogInPasswordless(login, messageParameters)
    } else {
      return userManagementService.initiateSignUpWithEmailOrPhone(login, null, messageParameters)
    }
  }

  /**
   * @description Completes sign in
   * @param token - received from #signIn method
   * @param confirmationCode - OTP sent by AWS Cognito/SES
   * @param options - optional parameters for CommonNetworkMember initialization
   * @returns an object with a flag, identifying whether new account was created, and initialized instance of SDK
   */
  static async confirmSignIn<T extends DerivedType<T>>(
    this: T,
    token: string,
    confirmationCode: string,
    options: ExtractOptionsType<T>,
  ): Promise<{ isNew: boolean; commonNetworkMember: InstanceType<T> }> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: token },
      { isArray: false, type: 'confirmationCode', isRequired: true, value: confirmationCode },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    // NOTE: loginToken = '{"ChallengeName":"CUSTOM_CHALLENGE","Session":"...","ChallengeParameters":{"USERNAME":"...","email":"..."}}'
    //       signUpToken = 'username::password'
    const isSignUpToken = token.split('::')[1] !== undefined

    if (isSignUpToken) {
      const commonNetworkMember = await this.confirmSignUp(token, confirmationCode, options)

      return { isNew: true, commonNetworkMember }
    }

    const commonNetworkMember = await this.completeLoginChallenge(token, confirmationCode, options)

    return { isNew: false, commonNetworkMember }
  }

  /**
   * @description Initiates change user password
   * @param oldPassword
   * @param newPassword
   * @param options - optional parameters with specified environment
   */
  async changePassword(oldPassword: string, newPassword: string, options: SdkOptions): Promise<void> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: oldPassword },
      { isArray: false, type: 'string', isRequired: true, value: newPassword },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    this.cognitoUserTokens = await userManagementService.changePassword(
      this.cognitoUserTokens,
      oldPassword,
      newPassword,
    )
  }

  /**
   * @description Initiates change user attribute (email/phoneNumber) flow
   * @param newLogin - new email/phoneNumber
   * @param options - optional parameters with specified environment
   * @param messageParameters - optional parameters with specified welcome message
   */
  // NOTE: operation is used for change the attribute, not username. Consider renaming
  //       New email/phoneNumber can be useded as a username to login.
  async changeUsername(newLogin: string, options: SdkOptions, messageParameters?: MessageParameters): Promise<void> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: newLogin },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
      { isArray: false, type: MessageParameters, isRequired: false, value: messageParameters },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    this.cognitoUserTokens = await userManagementService.initiateChangeLogin(
      this.cognitoUserTokens,
      newLogin,
      messageParameters,
    )
  }

  /**
   * @description Completes change user attribute (email/phoneNumber) flow
   * @param newUsername - new email/phoneNumber
   * @param confirmationCode - OTP sent by AWS Cognito/SES
   * @param options - optional parameters with specified environment
   */
  async confirmChangeUsername(newLogin: string, confirmationCode: string, options: SdkOptions): Promise<void> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: newLogin },
      { isArray: false, type: 'confirmationCode', isRequired: true, value: confirmationCode },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    this.cognitoUserTokens = await userManagementService.completeChangeLogin(
      this.cognitoUserTokens,
      newLogin,
      confirmationCode,
    )
  }

  /**
   * @description Generates random seed from which keys could be derived
   */
  static async generateSeed(didMethod: string = DEFAULT_DID_METHOD): Promise<any> {
    await ParametersValidator.validate([{ isArray: false, type: 'didMethod', isRequired: true, value: didMethod }])

    let seed
    switch (didMethod) {
      case 'jolo':
        seed = await randomBytes(32)
        break
      default:
        seed = await randomBytes(32)
    }

    return seed
  }

  /* istanbul ignore next: protected method */
  protected async saveEncryptedCredentials(data: any, storageRegion?: string): Promise<any[]> {
    return this._walletStorageService.saveCredentials(data, storageRegion)
  }

  /**
   * @description Deletes all credentials from the wallet
   * @param storageRegion (string) - (optional) specify region where credentials will be stored
   */
  async deleteAllCredentials(storageRegion?: string): Promise<void> {
    return this._walletStorageService.deleteAllCredentials(storageRegion)
  }

  /**
   * @description Creates JWT of credential offer request
   * @param offeredCredentials - array of credentials to be offered
   * @param options - optional, JwtOptions containing:
   *
   *   audienceDid (string) - audience of generated token
   *
   *   expiresAt (isoString) - expire date-time of generated token
   *
   *   nonce (string) - nonce/jti of generated token
   *
   *   callbackUrl (string)
   * @returns JWT
   */
  async generateCredentialOfferRequestToken(
    offeredCredentials: OfferedCredential[],
    options?: JwtOptions,
  ): Promise<string> {
    await ParametersValidator.validate([
      { isArray: true, type: OfferedCredential, isRequired: true, value: offeredCredentials },
      { isArray: false, type: JwtOptions, isRequired: false, value: options },
    ])

    const { audienceDid, expiresAt, nonce, callbackUrl } = options ?? {}
    const params = {
      offeredCredentials,
      audienceDid,
      expiresAt,
      nonce,
      callbackUrl,
    }

    const {
      body: { credentialOffer },
    } = await this._issuerApiService.buildCredentialOffer(params)

    const signedObject = this._keysService.signJWT(credentialOffer as any, this.didDocumentKeyId)

    return this._jwtService.encodeObjectToJWT(signedObject)
  }

  async generateDidAuthRequest(options?: JwtOptions): Promise<string> {
    await ParametersValidator.validate([{ isArray: false, type: JwtOptions, isRequired: false, value: options }])

    return this.generateCredentialShareRequestToken([], null, options)
  }

  /**
   * @description Creates JWT of credential share request
   * @param credentialRequirements - array of credential requirements with credential types
   * @param issuerDid - DID of the issuer
   * @param options - optional, JwtOptions containing:
   *
   *   audienceDid (string) - audience of generated token
   *
   *   expiresAt (isoString) - expire date-time of generated token
   *
   *   nonce (number) - nonce/jti of generated token
   * @returns JWT
   */
  async generateCredentialShareRequestToken(
    credentialRequirements: CredentialRequirement[],
    issuerDid: string = undefined,
    options?: JwtOptions,
  ): Promise<string> {
    await ParametersValidator.validate([
      { isArray: true, type: CredentialRequirement, isRequired: true, value: credentialRequirements },
      { isArray: false, type: 'did', isRequired: false, value: issuerDid },
      { isArray: false, type: JwtOptions, isRequired: false, value: options },
    ])

    const { audienceDid, expiresAt, nonce, callbackUrl } = options ?? {}
    const params = {
      credentialRequirements,
      issuerDid,
      audienceDid,
      expiresAt,
      nonce,
      callbackUrl,
    }

    const {
      body: { credentialShareRequest },
    } = await this._verifierApiService.buildCredentialRequest(params)

    const signedObject = this._keysService.signJWT(credentialShareRequest as any, this.didDocumentKeyId)

    return this._jwtService.encodeObjectToJWT(signedObject)
  }

  /**
   * @description Creates JWT of credential offer response
   * @param credentialOfferToken - JWT with offered credentials
   * @returns JWT
   */
  async createCredentialOfferResponseToken(credentialOfferToken: string): Promise<string> {
    await ParametersValidator.validate([{ isArray: false, type: 'jwt', isRequired: true, value: credentialOfferToken }])

    const credentialOfferResponse = await this._holderService.buildCredentialOfferResponse(credentialOfferToken)

    const signedObject = this._keysService.signJWT(credentialOfferResponse, this.didDocumentKeyId)

    return this._jwtService.encodeObjectToJWT(signedObject)
  }

  async createDidAuthResponse(didAuthRequestToken: string): Promise<string> {
    await ParametersValidator.validate([{ isArray: false, type: 'jwt', isRequired: true, value: didAuthRequestToken }])

    return this.createCredentialShareResponseToken(didAuthRequestToken, [])
  }

  // NOTE: to be removed after support of legacy credentials is dropped
  /* istanbul ignore next: private method */
  private _validateSignedCredentialsSupportedStructures(credentials: SignedCredential[]) {
    const errors: string[] = []

    for (const credential of credentials) {
      const hasIssuedDate = typeof credential.issued !== 'undefined'
      const hasIssuanceDate = typeof credential.issuanceDate !== 'undefined'
      const isLegacyCredential = typeof credential.claim !== 'undefined'
      const hasCredentialSubject = typeof credential.credentialSubject !== 'undefined'

      if (isLegacyCredential) {
        if (!hasIssuedDate) {
          const error = 'Parameter "issued" is missing for SignedCredential'

          errors.push(error)
        }

        continue
      }

      if (!hasIssuanceDate) {
        const error = 'Parameter "issuanceDate" is missing for SignedCredential'

        errors.push(error)
      }

      if (!hasCredentialSubject) {
        const error = 'Parameter "credentialSubject" is missing for SignedCredential'

        errors.push(error)
      }
    }

    const areCredentialsValid = errors.length === 0

    if (!areCredentialsValid) {
      throw new SdkErrorFromCode('COR-1', { errors, credentials })
    }
  }

  /**
   * @description Creates JWT of credential share response
   * @param credentialShareRequestToken - JWT with the requested VCs
   * @param suppliedCredentials - array of signed credentials
   * @returns JWT
   */
  async createCredentialShareResponseToken(
    credentialShareRequestToken: string,
    suppliedCredentials: SignedCredential[],
  ): Promise<string> {
    await ParametersValidator.validate([
      { isArray: false, type: 'jwt', isRequired: true, value: credentialShareRequestToken },
      { isArray: true, type: SignedCredential, isRequired: true, value: suppliedCredentials },
    ])

    this._validateSignedCredentialsSupportedStructures(suppliedCredentials)

    const credentialResponse = await this._holderService.buildCredentialResponse(
      credentialShareRequestToken,
      suppliedCredentials,
    )

    const signedObject = this._keysService.signJWT(credentialResponse, this.didDocumentKeyId)

    return this._jwtService.encodeObjectToJWT(signedObject)
  }

  /**
   * @description Returns user's DID
   * @returns DID
   */
  get did() {
    const didCalculated = this._did

    /* istanbul ignore else: code simplicity */
    if (!didCalculated) {
      this._did = this._didDocumentService.getMyDid()
    }

    return this._did
  }

  /**
   * @description Returns user's DID document key ID
   * @returns key ID
   */
  get didDocumentKeyId() {
    if (!this._didDocumentKeyId) {
      this._didDocumentKeyId = this._didDocumentService.getKeyId(this.did)
    }

    return this._didDocumentKeyId
  }

  /**
   * @description Returns credential types credential request token
   * @param credentialRequest - object with credential requirements
   * @returns array of credential types
   */
  getCredentialTypes(credentialRequest: any): any[] {
    // await ParametersValidator.validateSync(
    //   [
    //     { isArray: false, type: 'object', isRequired: true, value: credentialRequest }
    //   ]
    // )

    const { interactionToken } = credentialRequest.payload
    const { credentialRequirements } = interactionToken
    const credentialTypes = []

    for (const credential of credentialRequirements) {
      if (isW3cCredential(credential)) {
        const type = credential.type[1] // seems its always next structure type: ['Credential', 'ProofOfEmailCredential|....']
        credentialTypes.push(type)
      }
    }

    return credentialTypes
  }

  /**
   * @description Parses JWT token (request and response tokens of share and offer flows)
   * @param token - JWT
   * @returns parsed object from JWT
   */
  static fromJWT(token: string): any {
    // await ParametersValidator.validateSync(
    //   [
    //     { isArray: false, type: 'jwt', isRequired: true, value: token }
    //   ]
    // )

    return JwtService.fromJWT(token)
  }

  async buildRevocationListStatus(unsignedCredential: any, revocationServiceAccessToken: string): Promise<any> {
    const credentialId = unsignedCredential.id
    const subjectDid = unsignedCredential.holder?.id

    const {
      body: { credentialStatus, revocationListCredential },
    } = await this._revocationApiService.buildRevocationListStatus(revocationServiceAccessToken, {
      credentialId,
      subjectDid,
    })

    const revokableUnsignedCredential = Object.assign({}, unsignedCredential, { credentialStatus })
    revokableUnsignedCredential['@context'].push('https://w3id.org/vc-revocation-list-2020/v1')

    if (revocationListCredential) {
      const revocationSignedListCredential = await this._affinity.signCredential(
        revocationListCredential as any,
        this._encryptedSeed,
        this._password,
      )
      revocationSignedListCredential.issuanceDate = new Date().toISOString()

      await this._revocationApiService.publishRevocationListCredential(
        revocationServiceAccessToken,
        revocationSignedListCredential,
      )
    }

    return revokableUnsignedCredential
  }

  async revokeCredential(
    credentialId: string,
    revocationReason: string,
    revocationServiceAccessToken: string,
  ): Promise<void> {
    const accessToken = revocationServiceAccessToken

    const {
      body: { revocationListCredential },
    } = await this._revocationApiService.revokeCredential(accessToken, { id: credentialId, revocationReason })

    const revocationSignedListCredential = await this._affinity.signCredential(
      revocationListCredential,
      this._encryptedSeed,
      this._password,
    )
    revocationSignedListCredential.issuanceDate = new Date().toISOString()

    await this._revocationApiService.publishRevocationListCredential(accessToken, revocationSignedListCredential)
  }

  /**
   * @description Signs credentials
   * @param credentialOfferResponseToken - credential offer response JWT
   * @param credentialParams - params for credentials
   * @returns array of SignedCredential
   */
  async signCredentials(credentialOfferResponseToken: string, credentialParams: VCV1Unsigned[]): Promise<VCV1[]> {
    await ParametersValidator.validate([
      { isArray: false, type: 'jwt', isRequired: true, value: credentialOfferResponseToken },
      { isArray: true, type: 'object', isRequired: true, value: credentialParams },
    ])

    const signedCredentials = []
    const credentialOfferResponse = CommonNetworkMember.fromJWT(credentialOfferResponseToken)
    const { selectedCredentials } = credentialOfferResponse.payload.interactionToken

    const credentialTypesThatCanBeSigned: string[] = selectedCredentials.map(({ type }: any) => type)

    for (const unsignedCredential of credentialParams) {
      const isCredentialOffered = unsignedCredential.type.some((type) => credentialTypesThatCanBeSigned.includes(type))

      if (!isCredentialOffered) {
        continue
      }

      const { credentialSubject, type, '@context': context, expirationDate } = unsignedCredential

      const credentialMetadata = { type, context }
      const signedCredential = await this.signCredential(
        credentialSubject,
        credentialMetadata,
        { credentialOfferResponseToken },
        expirationDate,
      )

      signedCredentials.push(signedCredential)
    }

    if (signedCredentials.length === 0) {
      throw new SdkErrorFromCode('COR-22', { credentialOfferResponseToken, credentialParams })
    }

    return signedCredentials
  }

  /**
   * @description Signs credential
   * @param claim - data which should be present in VC according to VC schema,
   * e.g. const claim = { ageOver: 18 }
   * @param claimMetadata - schema of credential
   * @param signCredentialOptionalInput - object with optional
   * credential offer response JWT and requester DID
   * @param expiresAt - optional, date-time when VC is to be expired
   * @returns signed credential object
   */
  async signCredential<Subject extends VCV1SubjectBaseMA>(
    credentialSubject: Subject,
    claimMetadata: ClaimMetadata,
    signCredentialOptionalInput: SignCredentialOptionalInput,
    expiresAt?: string,
  ): Promise<VCV1> {
    await ParametersValidator.validate([
      { isArray: false, type: 'object', isRequired: true, value: credentialSubject },
      { isArray: false, type: ClaimMetadata, isRequired: true, value: claimMetadata },
      { isArray: false, type: SignCredentialOptionalInput, isRequired: true, value: signCredentialOptionalInput },
      { isArray: false, type: 'isoString', isRequired: false, value: expiresAt },
    ])

    if (typeof expiresAt !== 'undefined' && new Date().getTime() > new Date(expiresAt).getTime()) {
      throw new Error('Expiry date should be greater than current date')
    }

    let { requesterDid } = signCredentialOptionalInput
    const { credentialOfferResponseToken } = signCredentialOptionalInput

    /* istanbul ignore else: code simplicity */
    if (credentialOfferResponseToken) {
      const credentialOfferResponse = JwtService.fromJWT(credentialOfferResponseToken)
      requesterDid = credentialOfferResponse.payload.iss
    }

    const unsignedCredential = buildVCV1Unsigned({
      skeleton: buildVCV1Skeleton({
        id: `claimId:${randomBytes(8).toString('hex')}`,
        credentialSubject,
        holder: { id: parse(requesterDid).did },
        type: claimMetadata.type,
        context: claimMetadata.context,
      }),
      issuanceDate: new Date().toISOString(),
      expirationDate: expiresAt ? new Date(expiresAt).toISOString() : undefined,
    })

    return this._affinity.signCredential(unsignedCredential, this._encryptedSeed, this._password)
  }

  /**
   * @description Initiates the phone number verification flow
   * @deprecated
   * @param config - Configuration options
   * @param config.apiKey - They api access key to the issuer service
   * @param config.phoneNumber - The phone number to send the confirmation code to
   * @param config.isWhatsAppNumber - Whether the phone number is a WhatsApp number
   * @param config.id - The id of the request, this is for the caller to be able to identify the credential in the verify step
   * @param config.holder - The DID of the user who will recieve the VC (owner of the phone number)
   * @returns intitiate response data, including the status of the request
   */
  async initiatePhoneCredential({
    apiKey,
    phoneNumber,
    isWhatsAppNumber,
    id,
    holder,
  }: {
    apiKey: string
    phoneNumber: string
    isWhatsAppNumber?: boolean
    id: string
    holder: string
  }): Promise<PhoneIssuerInitiateResponse> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: apiKey },
      { isArray: false, type: 'string', isRequired: true, value: phoneNumber },
      { isArray: false, type: 'boolean', isRequired: false, value: isWhatsAppNumber },
      { isArray: false, type: 'string', isRequired: true, value: id },
      { isArray: false, type: 'string', isRequired: true, value: holder },
    ])

    return this._phoneIssuer.initiate({ apiKey, phoneNumber, isWhatsAppNumber, id, holder })
  }

  /**
   * @description Finishes the phone number verification flow
   * @deprecated
   * @param config - Configuration options
   * @param config.apiKey - They api access key to the issuer service
   * @param config.code - The code the user recieved
   * @param config.id - The id of the request, must match the ID given in the initiate step
   * @param config.holder - The DID of the user who will recieve the VC (owner of the phone number)
   * @returns verify response data, including the issued VC(s)
   */
  async verifyPhoneCredential({
    apiKey,
    code,
    id,
    holder,
  }: {
    apiKey: string
    code: string
    id: string
    holder: string
  }): Promise<PhoneIssuerVerifyResponse> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: apiKey },
      { isArray: false, type: 'string', isRequired: true, value: code },
      { isArray: false, type: 'string', isRequired: true, value: id },
      { isArray: false, type: 'string', isRequired: true, value: holder },
    ])

    return this._phoneIssuer.verify({ apiKey, code, id, holder })
  }

  /**
   * @description Initiates the email address verification flow
   * @deprecated
   * @param config - Configuration options
   * @param config.apiKey - They api access key to the issuer service
   * @param config.emailAddress - The email address to send the confirmation code to
   * @param config.id - The id of the request, this is for the caller to be able to identify the credential in the verify step
   * @param config.holder - The DID of the user who will recieve the VC (owner of the email address)
   * @returns intitiate response data, including the status of the request
   */
  async initiateEmailCredential({
    apiKey,
    emailAddress,
    id,
    holder,
  }: {
    apiKey: string
    emailAddress: string
    id: string
    holder: string
  }): Promise<EmailIssuerInitiateResponse> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: apiKey },
      { isArray: false, type: 'string', isRequired: true, value: emailAddress },
      { isArray: false, type: 'string', isRequired: true, value: id },
      { isArray: false, type: 'string', isRequired: true, value: holder },
    ])

    return this._emailIssuer.initiate({ apiKey, emailAddress, id, holder })
  }

  /**
   * @description Finishes the email address verification flow
   * @deprecated
   * @param config - Configuration options
   * @param config.apiKey - They api access key to the issuer service
   * @param config.code - The code the user recieved
   * @param config.id - The id of the request, must match the ID given in the initiate step
   * @param config.holder - The DID of the user who will recieve the VC (owner of the email address)
   * @returns verify response data, including the issued VC(s)
   */
  async verifyEmailCredential({
    apiKey,
    code,
    id,
    holder,
  }: {
    apiKey: string
    code: string
    id: string
    holder: string
  }): Promise<EmailIssuerVerifyResponse> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: true, value: apiKey },
      { isArray: false, type: 'string', isRequired: true, value: code },
      { isArray: false, type: 'string', isRequired: true, value: id },
      { isArray: false, type: 'string', isRequired: true, value: holder },
    ])

    return this._emailIssuer.verify({ apiKey, code, id, holder })
  }

  async verifyDidAuthResponse(
    didAuthResponseToken: string,
    didAuthRequestToken?: string,
  ): Promise<CredentialShareResponseOutput> {
    await ParametersValidator.validate([
      { isArray: false, type: 'jwt', isRequired: true, value: didAuthResponseToken },
      { isArray: false, type: 'jwt', isRequired: false, value: didAuthRequestToken },
    ])

    return this.verifyCredentialShareResponseToken(didAuthResponseToken, didAuthRequestToken)
  }

  /**
   * @description Validates response token, verifies signature on provided VCs
   * and expiration date of VCs
   * @param credentialShareResponseToken - optional, used if need to check
   * response against request (when request have constrains)
   * @param credentialShareRequestToken - JWT with requested VC
   * @param shouldOwn - optional (boolean), can be passed as true,
   * when needed to verify if holder is a subject of VC
   * @returns { isValid, did, jti, suppliedCredentials, errors }
   *
   * isValid - boolean, result of the verification
   *
   * did - DID of the issuer
   *
   * jti - unique identifier for the JWT
   *
   * suppliedCredentials - array of supplied credentials
   */
  async verifyCredentialShareResponseToken(
    credentialShareResponseToken: string,
    credentialShareRequest?: any,
    shouldOwn: boolean = true,
  ): Promise<CredentialShareResponseOutput> {
    let credentialShareRequestToken
    const isFunction = credentialShareRequest instanceof Function
    if (!isFunction) {
      credentialShareRequestToken = credentialShareRequest
    }

    const paramsToValidate = [
      { isArray: false, type: 'jwt', isRequired: true, value: credentialShareResponseToken },
      { isArray: false, type: 'jwt', isRequired: false, value: credentialShareRequestToken },
      { isArray: false, type: 'boolean', isRequired: false, value: shouldOwn },
    ]

    await ParametersValidator.validate(paramsToValidate)

    if (isFunction) {
      const credentialShareResponse = CommonNetworkMember.fromJWT(credentialShareResponseToken)
      const requestNonce: string = credentialShareResponse.payload.jti
      credentialShareRequestToken = await credentialShareRequest(requestNonce)

      if (!credentialShareRequestToken) {
        throw new SdkErrorFromCode('COR-15', { credentialShareRequestToken })
      }

      try {
        CommonNetworkMember.fromJWT(credentialShareRequestToken)
      } catch (error) {
        throw new SdkErrorFromCode('COR-15', { credentialShareRequestToken })
      }
    }

    const response = await this._holderService.verifyCredentialShareResponse(
      credentialShareResponseToken,
      credentialShareRequestToken,
      shouldOwn,
    )

    const { isValid, did, jti, suppliedCredentials, errors } = response

    const isTestEnvironment = process.env.NODE_ENV === 'test'

    if (isValid && !isTestEnvironment) {
      this._sendVCVerifiedPerPartyMetrics(suppliedCredentials)
    }

    return { isValid, did, nonce: jti, suppliedCredentials, errors }
  }

  /* istanbul ignore next: private method */
  private _sendVCVerifiedPerPartyMetrics(credentials: any[]) {
    const verifierDid = this.did

    for (const credential of credentials) {
      const metadata = this._metricsService.parseVcMetadata(credential, EventName.VC_VERIFIED_PER_PARTY)
      this._sendVCVerifiedPerPartyMetric(credential.id, verifierDid, metadata)
    }
  }

  /* istanbul ignore next: private method */
  private _sendVCVerifiedPerPartyMetric(vcId: string, verifierDid: string, metadata: EventMetadata) {
    const event = {
      component: this._component,
      link: vcId,
      secondaryLink: verifierDid,
      name: EventName.VC_VERIFIED_PER_PARTY,
      category: EventCategory.VC,
      subCategory: 'verify per party',
      metadata: metadata,
    }

    this._metricsService.send(event)
  }

  private _sendVCSavedMetric(vcId: string, issuerId: string, metadata: EventMetadata) {
    const event = {
      component: this._component,
      link: vcId,
      secondaryLink: issuerId,
      name: EventName.VC_SAVED,
      category: EventCategory.VC,
      subCategory: 'save',
      metadata: metadata,
    }

    this._metricsService.send(event)
  }

  protected _sendVCSavedMetrics(credentials: SignedCredential[]) {
    for (const credential of credentials) {
      if (isW3cCredential(credential)) {
        const metadata = this._metricsService.parseVcMetadata(credential, EventName.VC_SAVED)
        const vcId = credential.id
        // the issuer property could be either an URI string or an object with id propoerty
        // https://www.w3.org/TR/vc-data-model/#issuer
        let issuerId: string
        const issuer = credential.issuer

        if (typeof issuer === 'string') {
          issuerId = issuer
        } else {
          issuerId = issuer.id
        }

        this._sendVCSavedMetric(vcId, issuerId, metadata)
      }
    }
  }

  /**
   * @description Validates offer response against offer request
   * @param credentialOfferResponseToken - JWT with credential offer response
   * @param credentialOfferRequestToken - JWT with credential offer request
   * @returns { isValid, did, jti, selectedCredentials, errors }
   *
   * isValid - boolean, result of the verification
   *
   * did - DID of the issuer
   *
   * jti - unique identifier for the JWT
   *
   * selectedCredentials - array of selected credentials
   */
  async verifyCredentialOfferResponseToken(
    credentialOfferResponseToken: string,
    credentialOfferRequestToken?: string,
  ): Promise<CredentialOfferResponseOutput> {
    await ParametersValidator.validate([
      { isArray: false, type: 'jwt', isRequired: true, value: credentialOfferResponseToken },
      { isArray: false, type: 'jwt', isRequired: false, value: credentialOfferRequestToken },
    ])

    const params = { credentialOfferResponseToken, credentialOfferRequestToken }

    const res = await this._issuerApiService.verifyCredentialOfferResponse(params)

    const { isValid, issuer, jti, selectedCredentials, errors } = res.body

    const did = DidDocumentService.keyIdToDid(issuer)

    return { isValid, did, nonce: jti, selectedCredentials, errors }
  }

  /*
   * W3C-spec VP methods
   */

  /**
   * @description Creates JWT of presentation challenge
   * @param credentialRequirements - array of credential requirements with credential types
   * @param issuerDid - DID of the issuer
   * @param options - optional, JwtOptions containing:
   *
   *   audienceDid (string) - audience of generated token
   *
   *   expiresAt (isoString) - expire date-time of generated token
   *
   *   nonce (number) - nonce/jti of generated token

   *   callbackUrl (string)
   * @returns JWT
   */
  async generatePresentationChallenge(
    credentialRequirements: CredentialRequirement[],
    issuerDid: string = undefined,
    options?: JwtOptions,
  ): Promise<string> {
    await ParametersValidator.validate([
      { isArray: true, type: CredentialRequirement, isRequired: true, value: credentialRequirements },
      { isArray: false, type: 'did', isRequired: false, value: issuerDid },
      { isArray: false, type: JwtOptions, isRequired: false, value: options },
    ])

    const { audienceDid, expiresAt, nonce, callbackUrl } = options ?? {}
    const params = {
      credentialRequirements,
      issuerDid,
      audienceDid,
      expiresAt,
      nonce,
      callbackUrl,
    }

    const {
      body: { credentialShareRequest },
    } = await this._verifierApiService.buildCredentialRequest(params)

    const signedObject = this._keysService.signJWT(credentialShareRequest as any)

    return this._jwtService.encodeObjectToJWT(signedObject)
  }

  /**
   * @description Creates VP from VP challenge and credentials
   * @param challenge - challenge with the requested VCs
   * @param vcs - array of signed credentials
   * @returns VPV1
   */
  async createPresentationFromChallenge(challenge: string, vcs: VCV1[], domain: string): Promise<VPV1> {
    await ParametersValidator.validate([
      { isArray: false, type: 'jwt', isRequired: true, value: challenge },
      { isArray: true, type: 'VCV1', isRequired: true, value: vcs },
    ])

    const requestedTypes = this.getCredentialTypes(CommonNetworkMember.fromJWT(challenge))

    return this._affinity.signPresentation({
      vp: buildVPV1Unsigned({
        id: `presentationId:${randomBytes(8).toString('hex')}`,
        vcs: vcs.filter((vc) => requestedTypes.includes(vc.type[1])),
        holder: { id: this.did },
      }),
      encryption: {
        seed: this._encryptedSeed,
        key: this._password,
      },
      purpose: {
        challenge,
        domain,
      },
    })
  }

  /**
   * @description Validates a VP, and the contained VCs
   * @param vp - the presentation to be validated
   * when needed to verify if holder is a subject of VC
   * @returns { isValid, did, challenge, suppliedPresentation, errors }
   *
   * isValid - boolean, result of the verification
   *
   * did - DID of the VP issuer (holder of the shared VCs)
   *
   * challenge - unique identifier for the presentation.
   * You are responsible for checking this to protect against replay attacks
   *
   * suppliedPresentation - the validated presentation
   *
   * errors - array of validation errors
   */
  async verifyPresentation(vp: unknown): Promise<PresentationValidationOutput> {
    const response = await this._affinity.validatePresentation(vp)

    if (response.result === true) {
      // After validating the VP we need to validate the VP's challenge token
      // to ensure that it was issued from the correct DID and that it hasn't expired.
      try {
        await this._holderService.verifyPresentationChallenge(response.data.proof.challenge, this.did)
      } catch (error) {
        return {
          isValid: false,
          suppliedPresentation: response.data,
          errors: [error],
        }
      }

      return {
        isValid: true,
        did: response.data.holder.id,
        challenge: response.data.proof.challenge,
        suppliedPresentation: response.data,
      }
    } else {
      return {
        isValid: false,
        suppliedPresentation: vp,
        errors: [response.error],
      }
    }
  }

  /**
   * @description Creates a new instance of SDK by access token
   * @param accessToken
   * @param options - optional parameters for AffinityWallet initialization
   * @returns initialized instance of SDK
   */
  static async fromAccessToken<T extends DerivedType<T>>(
    this: T,
    accessToken: string,
    options: ExtractOptionsType<T>,
  ): Promise<InstanceType<T>> {
    await ParametersValidator.validate([
      { isArray: false, type: 'string', isRequired: false, value: accessToken },
      { isArray: false, type: SdkOptions, isRequired: true, value: options },
    ])

    const keyManagementService = await CommonNetworkMember._createKeyManagementService(options)
    const { encryptedSeed, encryptionKey } = await keyManagementService.pullKeyAndSeed(accessToken)
    return new this(encryptionKey, encryptedSeed, options)
  }

  /**
   * @description Logins with access token of Cognito user registered in Affinity
   * @param options - optional parameters for AffinityWallet initialization
   * @returns initialized instance of SDK or throws `COR-9` UnprocessableEntityError,
   * if user is not logged in.
   */
  static async init<T extends DerivedType<T>>(this: T, options: ExtractOptionsType<T>): Promise<InstanceType<T>> {
    await ParametersValidator.validate([{ isArray: false, type: SdkOptions, isRequired: true, value: options }])

    const userManagementService = CommonNetworkMember._createUserManagementService(options)
    const { accessToken } = userManagementService.readUserTokensFromSessionStorage()
    const keyManagementService = CommonNetworkMember._createKeyManagementService(options)
    const { encryptedSeed, encryptionKey } = await keyManagementService.pullKeyAndSeed(accessToken)

    return new this(encryptionKey, encryptedSeed, options)
  }

  /**
   * @description Save's encrypted VCs in Affinity Guardian Wallet
   * 1. encrypt VCs
   * 2. store encrypted VCs in Affinity Guardian Wallet
   * @param data - array of VCs
   * @param storageRegion (string) - (optional) specify region where credentials will be stored
   * @returns array of ids for corelated records
   */
  async saveCredentials(data: any[], storageRegion?: string): Promise<any> {
    const result = await this._walletStorageService.saveCredentials(data, storageRegion)

    this._sendVCSavedMetrics(data)
    // NOTE: what if creds actually were not saved in the vault?
    //       follow up with Isaak/Dustin on this - should we parse the response
    //       to define if we need to send the metrics
    return result
  }

  /**
   * @description Retrieve only the credential
   * @param credentialId (string) - id for the VC in vault
   * @param storageRegion (string) - (optional) specify region where credentials will be stored
   * @returns a single VC
   */
  async getCredentialById(credentialId: string, storageRegion?: string): Promise<any> {
    return this._walletStorageService.getCredentialById(credentialId, storageRegion)
  }

  /**
   * @description Retrieve only the credential
   * @param storageRegion (string) - (optional) specify region where credentials will be stored
   * @returns a single VC
   */
  async getAllCredentials(types: string[][], storageRegion?: string): Promise<any> {
    return this._walletStorageService.getAllCredentials(types, storageRegion)
  }

  /**
   * @description Delete credential by id
   * @param credentialId (string) - credential to remove
   * @param storageRegion (string) - (optional) specify region where credentials will be stored
   */
  async deleteCredentialById(credentialId: string, storageRegion?: string): Promise<void> {
    return this._walletStorageService.deleteCredentialById(credentialId, storageRegion)
  }
}
