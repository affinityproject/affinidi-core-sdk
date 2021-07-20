'use strict'

import { expect } from 'chai'
import request from 'supertest'
import { decode as jwtDecode } from 'jsonwebtoken'
import { Affinity } from '@affinidi/common'
import { DidAuthService } from '@affinidi/affinidi-did-auth-lib'
import { buildVCV1Unsigned, buildVCV1Skeleton } from '@affinidi/vc-common'
import { VCSPhonePersonV1, getVCPhonePersonV1Context } from '@affinidi/vc-data'
import { CommonNetworkMember } from '../helpers/CommonNetworkMember'
import UserManagementService from '../../src/services/UserManagementService'

import {
  generateUsername,
  generateEmail,
  getAllOptionsForEnvironment,
  getBasicOptionsForEnvironment,
  testSecrets,
} from '../helpers'
import credential from '../factory/signedCredential'

const {
  PASSWORD,
  COGNITO_PASSWORD,
  COGNITO_USERNAME,
  COGNITO_PHONE_NUMBER,
  COGNITO_USERNAME_NO_KEY,
  COGNITO_USER_UNCONFIRMED,
  COGNITO_USERNAME_EXISTS,
  ENCRYPTED_SEED_JOLO,
  ENCRYPTED_SEED_ELEM,
  DID_ELEM_SHORT,
  DID_ELEM_PARAMS,
  DID_JOLO,
  ISSUER_ENCRYPTED_SEED,
  HOLDER_PASSWORD,
  HOLDER_ENCRYPTED_SEED,
  UPDATING_ENCRYPTED_SEED,
  UPDATING_DID,
  ISSUER_ELEM_SEED,
} = testSecrets

const password = PASSWORD
const encryptedSeed = ENCRYPTED_SEED_JOLO
const encryptedSeedElem = ENCRYPTED_SEED_ELEM
const didElemShort = DID_ELEM_SHORT
const didElem = `${didElemShort};${DID_ELEM_PARAMS}`
const seedDid = DID_JOLO

const elemDidMethod = 'elem'
const joloDidMethod = 'jolo'

const phoneNumber = COGNITO_PHONE_NUMBER

const cognitoUsername = COGNITO_USERNAME
const cognitoPassword = COGNITO_PASSWORD

const userWithoutKey = COGNITO_USERNAME_NO_KEY
const emailUnconfirmed = COGNITO_USER_UNCONFIRMED

const options = getBasicOptionsForEnvironment()

describe('CommonNetworkMember', () => {
  const callbackUrl = 'https://kudos-issuer-backend.affinity-project.org/kudos_offering/'

  const offeredCredentials = [
    {
      type: 'TestDenisCred',
    },
  ]

  const credentialRequirements = [
    {
      type: ['Credential', 'TestDenisCred'],
    },
  ]

  it('returns true when user is UNCONFIRMED', async () => {
    const username = emailUnconfirmed

    const isUnconfirmed = await CommonNetworkMember.isUserUnconfirmed(username, options)

    expect(isUnconfirmed).to.equal(true)
  })

  // NOTE random failing issue, might be related to resolving JOLO DID
  it.skip('#generateCredentialOfferRequestToken, #verifyCredentialOfferResponseToken, #signCredentials, #validateCredential', async () => {
    const issuerPassword = password
    const issuerEncryptedSeed = ISSUER_ENCRYPTED_SEED

    const holderPassword = HOLDER_PASSWORD
    const holderEncryptedSeed = HOLDER_ENCRYPTED_SEED

    const renderInfo = {}
    const callbackUrl = 'https://kudos-issuer-backend.affinity-project.org/receive/testerBadge'

    const offeredCredentials = [
      {
        type: 'EntityCredential',
        renderInfo,
      },
      {
        type: 'PhoneCredentialPersonV1',
        renderInfo,
      },
    ]

    const commonNetworkMemberIssuer = new CommonNetworkMember(issuerPassword, issuerEncryptedSeed, options)
    const commonNetworkMemberHolder = new CommonNetworkMember(holderPassword, holderEncryptedSeed, options)
    const credentialOfferRequestToken = await commonNetworkMemberIssuer.generateCredentialOfferRequestToken(
      offeredCredentials,
      {
        callbackUrl,
      },
    )

    const credentialOfferResponseToken = await commonNetworkMemberHolder.createCredentialOfferResponseToken(
      credentialOfferRequestToken,
    )

    const {
      isValid,
      did: requesterDid,
      nonce,
      selectedCredentials,
    } = await commonNetworkMemberIssuer.verifyCredentialOfferResponseToken(
      credentialOfferResponseToken,
      credentialOfferRequestToken,
    )

    expect(requesterDid).to.exist
    expect(selectedCredentials).to.deep.equal(offeredCredentials)
    expect(nonce).to.exist
    expect(isValid).to.equal(true)
    expect(selectedCredentials).to.exist

    const unsignedCredentials = [
      buildVCV1Unsigned({
        skeleton: buildVCV1Skeleton<VCSPhonePersonV1>({
          id: 'urn:uuid:9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
          credentialSubject: {
            data: {
              '@type': ['Person', 'PersonE', 'PhonePerson'],
              telephone: '+1 555 555 5555',
            },
          },
          holder: { id: 'placeholder' },
          type: 'PhoneCredentialPersonV1',
          context: getVCPhonePersonV1Context(),
        }),
        issuanceDate: new Date().toISOString(),
        expirationDate: new Date(new Date().getTime() + 10 * 60 * 1000).toISOString(),
      }),
    ]

    const signedCredentials = await commonNetworkMemberIssuer.signCredentials(
      credentialOfferResponseToken,
      unsignedCredentials,
    )

    expect(signedCredentials).to.exist
    expect(signedCredentials).have.lengthOf(1)

    const affinityOptions = Object.assign({}, options, { apiKey: options.accessApiKey })

    const affinity = new Affinity(affinityOptions)
    const validateCredentialsResponse = await affinity.validateCredential(signedCredentials[0])

    expect(validateCredentialsResponse).to.deep.equal({ result: true, error: '' })
  })

  it('removes user if it is "UNCONFIMRED" before sign up', async () => {
    const email = generateEmail()

    await CommonNetworkMember.signUp(email, cognitoPassword, options)

    const token = await CommonNetworkMember.signUp(email, cognitoPassword, options)
    expect(token).to.exist
  })

  it('#throws `COR-4 / 400` when UNCONFIRMED user login', async () => {
    const username = emailUnconfirmed

    await CommonNetworkMember.signUp(username, cognitoPassword, options)

    let responseError

    try {
      await CommonNetworkMember.fromLoginAndPassword(username, cognitoPassword, options)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode, context } = responseError

    expect(code).to.equal('COR-4')
    expect(httpStatusCode).to.equal(404)
    expect(context.username).to.equal(username)
  })

  // This started failing with this error: LimitExceededException: Attempt limit exceeded, please try after some time.
  // Also it's not clear how this tests the resending of the OTP.
  it('resends OTP when UNCONFIRMED user signs up (for the Nth time)', async () => {
    const username = emailUnconfirmed

    await CommonNetworkMember.signUp(username, cognitoPassword, options)

    const token = await CommonNetworkMember.signUp(username, cognitoPassword, options)

    expect(token).to.equal(`${username}::${cognitoPassword}`)
  })

  it('.register (default did method)', async () => {
    const { did, encryptedSeed } = await CommonNetworkMember.register(password, options)

    expect(did).to.exist
    expect(encryptedSeed).to.exist
  })

  it('.register (elem did method)', async () => {
    const optionsWithElemDid = Object.assign({}, options, { didMethod: elemDidMethod } as const)

    const { did, encryptedSeed } = await CommonNetworkMember.register(password, optionsWithElemDid)

    expect(did).to.exist
    expect(encryptedSeed).to.exist
    const [, didMethod] = did.split(':')
    expect(didMethod).to.be.equal(elemDidMethod)
  })

  it('.register (jolo did method)', async () => {
    const optionsWithJoloDid = Object.assign({}, options, { didMethod: joloDidMethod } as const)

    const { did, encryptedSeed } = await CommonNetworkMember.register(password, optionsWithJoloDid)

    expect(did).to.exist
    expect(encryptedSeed).to.exist
    const [, didMethod] = did.split(':')
    expect(didMethod).to.be.equal(joloDidMethod)
  })

  // NOTE: skipping due to often errors related to resolving JOLO DID
  it.skip('#resolveDid (jolo)', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)
    const didDocument = await commonNetworkMember.resolveDid(seedDid)

    expect(didDocument).to.exist

    expect(didDocument.id).to.be.equal(seedDid)
  })

  it('#resolveDid (elem)', async () => {
    const optionsWithElemDid = Object.assign({}, options, { didMethod: elemDidMethod } as const)

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, optionsWithElemDid)
    const didDocument = await commonNetworkMember.resolveDid(didElem)

    expect(didDocument).to.exist
    expect(didDocument.id).to.be.equal(didElemShort)
  })

  it('#resolveDid throws `COR-1 / 400` invalid operation parameter passed (empty string)', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.resolveDid('')
    } catch (error) {
      responseError = error
    }

    const { code, message, httpStatusCode } = responseError

    expect(code).to.equal('COR-1')
    expect(httpStatusCode).to.equal(400)
    expect(message).to.equal('Invalid operation parameters.')
  })

  it('#resolveDid throws `REG-1 / 404` if seed not found', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    const badSeed = 'did:jolo:non_existing_seed'

    try {
      await commonNetworkMember.resolveDid(badSeed)
    } catch (error) {
      responseError = error
    }

    const { code, message, httpStatusCode } = responseError

    expect(code).to.equal('REG-1')
    expect(httpStatusCode).to.equal(404)
    expect(message).to.equal('Requested did:jolo:non_existing_seed not exists at the ledger.')
  })

  it('#resolveDid ignores extra parameter', async () => {
    const optionsWithElemDid = Object.assign({}, options, { didMethod: elemDidMethod } as const)

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, optionsWithElemDid)
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const didDocument = await commonNetworkMember.resolveDid(didElem, '123')

    expect(didDocument).to.exist

    expect(didDocument.id).to.be.equal(didElemShort)
  })

  // NOTE: skipping due to often errors related to resolving JOLO DID
  it.skip('.updateDidDocument (jolo did method)', async () => {
    const updatingEncryoptedSeed = UPDATING_ENCRYPTED_SEED
    const updatingDid = UPDATING_DID

    expect(updatingDid).to.exist
    expect(updatingEncryoptedSeed).to.exist
    const [, didMethod] = updatingDid.split(':')
    expect(didMethod).to.be.equal(joloDidMethod)

    // TODO: when registry with conuntTransaction endpoint will be at staging - change to default env
    const commonNetworkMember = new CommonNetworkMember(password, updatingEncryoptedSeed, options)
    const didDocument = await commonNetworkMember.resolveDid(updatingDid)

    const { authentication } = didDocument
    const keyId = authentication[0]
    const keyNumber = Number(keyId.split('-')[1])
    const updatedAuthentication = [`${updatingDid}#keys-${keyNumber + 1}`]
    didDocument.authentication = updatedAuthentication
    await commonNetworkMember.updateDidDocument(didDocument)

    const updatedDidDocument = await commonNetworkMember.resolveDid(updatingDid)
    expect(updatedDidDocument.authentication).to.be.deep.equal(updatedAuthentication)
  })

  it('#buildRevocationListStatus, #revokeCredential', async () => {
    const fullOptions = getAllOptionsForEnvironment()
    const commonNetworkMember = new CommonNetworkMember(password, ISSUER_ELEM_SEED, fullOptions)
    const holderDid = commonNetworkMember.did
    const didAuthRequestParams = {
      audienceDid: holderDid,
    }
    const issuerServer = `https://revocation-api.${fullOptions.env}.affinity-project.org`
    const didRequestTokenResponse = await request(issuerServer)
      .post('/api/v1/did-auth/create-did-auth-request')
      .send(didAuthRequestParams)
      .set('Api-Key', fullOptions.accessApiKey)

    expect(didRequestTokenResponse.status).to.equal(200)
    expect(didRequestTokenResponse.body).to.exist

    const didRequestToken = didRequestTokenResponse.body

    const holderEncryptedSeed = ISSUER_ELEM_SEED
    const holderPassword = password
    const holderDidAuthServiceOptions = {
      encryptedSeed: holderEncryptedSeed,
      encryptionKey: holderPassword,
    }
    const didAuthService = new DidAuthService(holderDidAuthServiceOptions)
    const didResponseToken = await didAuthService.createDidAuthResponseToken(didRequestToken)

    expect(didResponseToken).to.exist

    const accessToken = didResponseToken

    const credId = new Date().toISOString()
    const unsignedCredential = buildVCV1Unsigned({
      skeleton: buildVCV1Skeleton<VCSPhonePersonV1>({
        id: `credId:${credId}`,
        credentialSubject: {
          data: {
            '@type': ['Person', 'PersonE', 'PhonePerson'],
            telephone: '+1 555 555 5555',
          },
        },
        holder: { id: holderDid },
        type: 'PhoneCredentialPersonV1',
        context: getVCPhonePersonV1Context(),
      }),
      issuanceDate: new Date().toISOString(),
      expirationDate: new Date(new Date().getTime() + 10 * 60 * 1000).toISOString(),
    })

    const revokableUnsignedCredential = await commonNetworkMember.buildRevocationListStatus(
      unsignedCredential,
      accessToken,
    )

    const affinityOptions = Object.assign({}, fullOptions, { apiKey: fullOptions.accessApiKey })
    const affinity = new Affinity(affinityOptions)
    expect(revokableUnsignedCredential.credentialStatus).to.exist
    const createdCredential = await affinity.signCredential(revokableUnsignedCredential, ISSUER_ELEM_SEED, password)

    const sucessResult = await affinity.validateCredential(createdCredential)
    expect(sucessResult.result).to.equal(true)

    await commonNetworkMember.revokeCredential(revokableUnsignedCredential.id, 'Status changed', accessToken)

    const failResult = await affinity.validateCredential(createdCredential)
    expect(failResult.result).to.equal(false)
  })

  it('#register and #signUpWithExistsEntity (userName is arbitrary) and #fromLoginAndPassword', async () => {
    const { did, encryptedSeed } = await CommonNetworkMember.register(password, options)
    const keyParams = { encryptedSeed, password }
    const username = did

    const affinityWallet = await CommonNetworkMember.signUpWithExistsEntity(
      keyParams,
      username,
      cognitoPassword,
      options,
    )
    expect(affinityWallet).to.be.an.instanceof(CommonNetworkMember)
    if (typeof affinityWallet === 'string') {
      expect.fail('TS type guard')
    }

    const walletShortDid = affinityWallet.did.split(';elem:')[0]
    expect(walletShortDid).to.equal(did)

    const affinityWalletAfterLogin = await CommonNetworkMember.fromLoginAndPassword(username, cognitoPassword, options)
    const walletAfterLoginShortDid = affinityWalletAfterLogin.did.split(';elem:')[0]
    expect(walletAfterLoginShortDid).to.equal(did)
  })

  it('#register and #signUpWithExistsEntity (userName is arbitrary with week password) and #fromLoginAndPassword', async () => {
    const userPassword = '092376'
    const { did, encryptedSeed } = await CommonNetworkMember.register(password, options)
    const keyParams = { encryptedSeed, password }
    const username = did

    const affinityWallet = await CommonNetworkMember.signUpWithExistsEntity(keyParams, username, userPassword, options)
    expect(affinityWallet).to.be.an.instanceof(CommonNetworkMember)
    if (typeof affinityWallet === 'string') {
      expect.fail('TS type guard')
    }

    const walletShortDid = affinityWallet.did.split(';elem:')[0]
    expect(walletShortDid).to.equal(did)

    const affinityWalletAfterLogin = await CommonNetworkMember.fromLoginAndPassword(username, userPassword, options)
    const walletAfterLoginShortDid = affinityWalletAfterLogin.did.split(';elem:')[0]
    expect(walletAfterLoginShortDid).to.equal(did)
  })

  it('#generateCredentialOfferRequestToken', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)
    const token = await commonNetworkMember.generateCredentialOfferRequestToken(offeredCredentials, { callbackUrl })

    expect(token).to.exist

    const commonNetworkMemberElem = new CommonNetworkMember(password, encryptedSeedElem, options)
    const tokenElem = await commonNetworkMemberElem.generateCredentialOfferRequestToken(offeredCredentials, {
      callbackUrl,
    })

    const jwtObject = CommonNetworkMember.fromJWT(tokenElem)

    const {
      payload: { interactionToken, iss, typ },
      signature,
    } = jwtObject
    const { offeredCredentials: credentials, callbackURL: url } = interactionToken

    expect(iss).to.exist
    expect(signature).to.exist
    expect(typ).to.equal('credentialOfferRequest')
    expect(offeredCredentials).to.deep.equal(credentials)
    expect(callbackUrl).to.equal(url)
  })

  it('#generateCredentialOfferRequestToken with JwtOptions', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)
    const commonNetworkMemberElem = new CommonNetworkMember(password, encryptedSeedElem, options)

    const customExpiresAt = '2022-04-15T00:00:00.000Z'
    const customNonce = '123123123'
    const audienceDid = seedDid
    const jwtOptions = { audienceDid, expiresAt: customExpiresAt, nonce: customNonce, callbackUrl }

    const token = await commonNetworkMember.generateCredentialOfferRequestToken(offeredCredentials, jwtOptions)
    expect(token).to.exist

    const tokenObject = CommonNetworkMember.fromJWT(token)
    const { payload } = tokenObject
    expect(payload.aud).to.be.equal(audienceDid)
    expect(payload.jti).to.be.equal(customNonce)
    expect(payload.exp).to.be.equal(new Date(customExpiresAt).getTime())

    const tokenElem = await commonNetworkMemberElem.generateCredentialOfferRequestToken(offeredCredentials, jwtOptions)
    expect(tokenElem).to.exist
  })

  it('#generateCredentialOfferRequestToken throws `ISS-11 / 400` when expiration date is the past', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)
    // const commonNetworkMemberElem = new CommonNetworkMember(password, encryptedSeedElem, options)

    const customExpiresAt = '2020-01-01T00:00:00.000Z'
    const jwtOptions = { expiresAt: customExpiresAt }

    let responseError

    try {
      await commonNetworkMember.generateCredentialOfferRequestToken(offeredCredentials, jwtOptions)
    } catch (error) {
      responseError = error
    }

    const { code, message, httpStatusCode } = responseError

    expect(code).to.equal('ISS-11')
    expect(message).to.equal('Invalid Request. ExpiresAt parameter should be in future.')
    expect(httpStatusCode).to.equal(400)
  })

  it('#generateCredentialOfferRequestToken throws `COR-1 / 400` when bad parameters passed', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      await commonNetworkMember.generateCredentialOfferRequestToken(callbackUrl)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode } = responseError

    expect(code).to.equal('COR-1')
    expect(httpStatusCode).to.equal(400)
  })

  it('#generateCredentialShareRequestToken', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)
    const issuerDid = seedDid
    const token = await commonNetworkMember.generateCredentialShareRequestToken(credentialRequirements, issuerDid, {
      callbackUrl,
    })

    expect(token).to.exist
  })

  it('#generateCredentialShareRequestToken when issuerDid not passed', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)
    const token = await commonNetworkMember.generateCredentialShareRequestToken(credentialRequirements, undefined, {
      callbackUrl,
    })

    expect(token).to.exist
  })

  it('#generateCredentialShareRequestToken with jwtOptions', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)
    const issuerDid = seedDid
    const customExpiresAt = '2022-04-15T00:00:00.000Z'
    const customNonce = '123123123'
    const audienceDid = 'did:jolo:testDID123'
    const jwtOptions = { audienceDid, expiresAt: customExpiresAt, nonce: customNonce, callbackUrl }

    const token = await commonNetworkMember.generateCredentialShareRequestToken(
      credentialRequirements,
      issuerDid,
      jwtOptions,
    )
    expect(token).to.exist

    const tokenObject = CommonNetworkMember.fromJWT(token)
    const { payload } = tokenObject

    expect(payload.aud).to.be.equal(audienceDid)
    expect(payload.jti).to.be.equal(customNonce)
    expect(payload.exp).to.be.equal(new Date(customExpiresAt).getTime())
  })

  it('#verifyCredentialShareResponseToken', async () => {
    const credentialShareResponseToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNhbGxiYWNrVVJMIjoiIiwic3VwcGxpZWRDcmVkZW50aWFscyI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLHsiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9OYW1lQ3JlZGVudGlhbFBlcnNvblYxIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZX19LCJkYXRhIjp7IkBpZCI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2RhdGEiLCJAY29udGV4dCI6W251bGwseyJAdmVyc2lvbiI6MS4xLCJAcHJvdGVjdGVkIjp0cnVlLCJAdm9jYWIiOiJodHRwczovL3NjaGVtYS5vcmcvIiwiTmFtZVBlcnNvbiI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9OYW1lUGVyc29uIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsIm5hbWUiOiJodHRwczovL3NjaGVtYS5vcmcvbmFtZSIsImdpdmVuTmFtZSI6Imh0dHBzOi8vc2NoZW1hLm9yZy9naXZlbk5hbWUiLCJmdWxsTmFtZSI6Imh0dHBzOi8vc2NoZW1hLm9yZy9mdWxsTmFtZSJ9fSwiUGVyc29uRSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9QZXJzb25FIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyJ9fSwiT3JnYW5pemF0aW9uRSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9Pcmdhbml6YXRpb25FIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsImhhc0NyZWRlbnRpYWwiOiJodHRwczovL3NjaGVtYS5vcmcvaGFzQ3JlZGVudGlhbCIsImluZHVzdHJ5IjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvaW5kdXN0cnkifX0sIkNyZWRlbnRpYWwiOnsiQGlkIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvQ3JlZGVudGlhbCIsIkBjb250ZXh0Ijp7IkB2ZXJzaW9uIjoxLjEsIkBwcm90ZWN0ZWQiOnRydWUsIkB2b2NhYiI6Imh0dHBzOi8vc2NoZW1hLm9yZy8iLCJkYXRlUmV2b2tlZCI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2RhdGVSZXZva2VkIiwicmVjb2duaXplZEJ5IjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvcmVjb2duaXplZEJ5In19LCJPcmdhbml6YXRpb25hbENyZWRlbnRpYWwiOnsiQGlkIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvT3JnYW5pemF0aW9uYWxDcmVkZW50aWFsIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsImNyZWRlbnRpYWxDYXRlZ29yeSI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2NyZWRlbnRpYWxDYXRlZ29yeSIsIm9yZ2FuaXphdGlvblR5cGUiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9vcmdhbml6YXRpb25UeXBlIiwiZ29vZFN0YW5kaW5nIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvZ29vZFN0YW5kaW5nIiwiYWN0aXZlIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvYWN0aXZlIiwicHJpbWFyeUp1cmlzZGljdGlvbiI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL3ByaW1hcnlKdXJpc2RpY3Rpb24iLCJpZGVudGlmaWVyIjoiaHR0cHM6Ly9zY2hlbWEub3JnL2lkZW50aWZpZXIifX19XX19XSwiaWQiOiJjbGFpbUlkOjYzYjVkMTFjMGQxYjU1NjYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSJdLCJob2xkZXIiOnsiaWQiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRhdGEiOnsiQHR5cGUiOlsiUGVyc29uIiwiUGVyc29uRSIsIk5hbWVQZXJzb24iXSwiZ2l2ZW5OYW1lIjoiRGVuaXNVcGRhdGVkIiwiZmFtaWx5TmFtZSI6IlBvcG92In19LCJpc3N1YW5jZURhdGUiOiIyMDIwLTAxLTE3VDA3OjA2OjM1LjQwM1oiLCJpc3N1ZXIiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSIsInByb29mIjp7InR5cGUiOiJFY2RzYVNlY3AyNTZrMVNpZ25hdHVyZTIwMTkiLCJjcmVhdGVkIjoiMjAyMC0xMC0xOVQxODoxNToyM1oiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBI3ByaW1hcnkiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJqd3MiOiJleUpoYkdjaU9pSkZVekkxTmtzaUxDSmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZGZRLi5zall0amhoOWpHM3lzMVZCd3BhMGJwY0JoV0t2dDU0NnIxdlYxX0U5YTIxdXUwOEFFVEI5MUZnLXBQN1F5eDVhVlU2N2hKTmt0c1RVR1FNbWxZLVE0USJ9fV19LCJleHAiOjI1MjQ2MTE2MDAwMDAsInR5cCI6ImNyZWRlbnRpYWxSZXNwb25zZSIsImp0aSI6IjgxYWEzMTAzMGQ2NDVhZjAiLCJhdWQiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSIsImlzcyI6ImRpZDplbGVtOkVpQjlSMHdiUUdyTGkzcEVlSGJwUTl1THFWYkpuVWtFMTJEUGhnMkhKR3diakE7ZWxlbTppbml0aWFsLXN0YXRlPWV5SndjbTkwWldOMFpXUWlPaUpsZVVwMlkwZFdlVmxZVW5CaU1qUnBUMmxLYW1OdFZtaGtSMVZwVEVOS2NtRlhVV2xQYVVscVkwaEtjR0pYUm5sbFUwbHpTVzFHYzFwNVNUWkphMVpVVFdwVk1sTjVTamtpTENKd1lYbHNiMkZrSWpvaVpYbEtRVmt5T1hWa1IxWTBaRU5KTmtsdGFEQmtTRUo2VDJrNGRtUjZUbkJhUXpWMlkyMWpkbU15Vm1wa1dFcHdaRWhyZG1ScVNXbE1RMHAzWkZkS2MyRlhUa3hhV0d0cFQyeDBOMGx0Ykd0SmFtOXBTVE5DZVdGWE1XaGpibXRwVEVOS01XTXlSbTVhVTBrMlNXNU9jRm95TlhCaWJXTnBURU5LTUdWWVFteEphbTlwVlRKV2FtTkVTVEZPYlhONFZtMVdlV0ZYV25CWk1rWXdZVmM1ZFZNeVZqVk5ha0Y0VDBOSmMwbHVRakZaYlhod1dUQjBiR1ZWYUd4bFEwazJTV3BCZWxwcVJYZFpNbFpwV21wU2FVMVVVVEpOUkVWNFRWUkpNazlFU21wTk1sa3dUa1JKZWxwVVJtaGFiVlUxV1dwU2FsbFVRbXhOZWsxNVRrUkZNbGx0V21oT2VrRXdUbGROTTAxSFNtdE5WMGt3V1dwc2FVMVRTamxNU0hOcFlWZFJhVTlwU1dwamJWWnFZak5hYkdOdWEybE1RMG94WXpKR2JscFRTVFpKYmtwc1dUSTVNbHBZU2pWSmFYZHBaRWhzZDFwVFNUWkpiRTVzV1ROQmVVNVVXbkpOVmxwc1kyMXNiV0ZYVG1oa1IyeDJZbXQwYkdWVVNYZE5WR2RwVEVOS2QyUlhTbk5oVjA1TVdsaHNTVnBZWjJsUGFVbDNUWHBWZWxsNmF6Vk5WMFV6V21wbmVscHRTbWhhUjFwdFRrUkthbHBYVlRWT1YxWnRUa1JuTUZscVFUVk9NbGt4VFZSV2JFMXRVbXRhVkZWNFRsUkJNazlYVVRGTlJGcG9XWHBGZUUxcWEzZE9iVVpvV2tScmFXWldNSE5KYlVZeFpFZG9iR0p1VW5CWk1rWXdZVmM1ZFVscWNHSkphVTUzWTIxc2RGbFlTalZKYkRCelNXMUdlbU15Vm5sa1IyeDJZbXN4YkdSSGFIWmFRMGsyVjNsSmFtTklTbkJpVjBaNVpWTktaR1pSSWl3aWMybG5ibUYwZFhKbElqb2liblpPVDE5eFlsSlBkakpSYURCZmVWOXpNVlk0ZEc1SFh6bGpiWEZYWmpKVVNETjViek50VkZWTVdUUnFSWFZxVlVWR01uRnVPWFpKYlV4aU1tWnlhRzVvTUVkcVdrdHNPRVpGUkhjd2EzcFRkSFJNVEdjaWZRI3ByaW1hcnkifQ.4db860fcb22fa9e887c4411ba5747e59f63e515e51aa240fc1543c532ea400d3162e7e58c6ec5e6f1446ad9e9af9936bc87e9002118cbf499ef7444ac7b6f607'
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)

    const { isValid, suppliedCredentials } = await commonNetworkMember.verifyCredentialShareResponseToken(
      credentialShareResponseToken,
      undefined,
      false,
    )

    expect(isValid).to.equal(true)
    expect(suppliedCredentials).to.exist
  })

  it('#verifyCredentialShareResponseToken function to pull request token passed', async () => {
    const credentialShareRequestToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNyZWRlbnRpYWxSZXF1aXJlbWVudHMiOlt7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJOYW1lQ3JlZGVudGlhbFBlcnNvblYxIl0sImNvbnN0cmFpbnRzIjpbeyI9PSI6W3sidmFyIjoiaXNzdWVyIn0sImRpZDplbGVtOkVpQmJmRXJyZ3FTU3ZBa19sM2pESXhXcUhhRWJDQUlKT2Uxb2JLMHB5ZmpqUnc7ZWxlbTppbml0aWFsLXN0YXRlPWV5SndjbTkwWldOMFpXUWlPaUpsZVVwMlkwZFdlVmxZVW5CaU1qUnBUMmxLYW1OdFZtaGtSMVZwVEVOS2NtRlhVV2xQYVVscVkwaEtjR0pYUm5sbFUwbHpTVzFHYzFwNVNUWkphMVpVVFdwVk1sTjVTamtpTENKd1lYbHNiMkZrSWpvaVpYbEtRVmt5T1hWa1IxWTBaRU5KTmtsdGFEQmtTRUo2VDJrNGRtUjZUbkJhUXpWMlkyMWpkbHBIYkd0TU0xbDRTV2wzYVdOSVZtbGlSMnhxVXpKV05VbHFjR0psZVVwd1drTkpOa2xwVG5kamJXeDBXVmhLTlVscGQybGtXRTVvV2pKVmFVOXBTbnBoVjJSMVlWYzFia2xwZDJsa1NHeDNXbE5KTmtsc1RteFpNMEY1VGxSYWNrMVdXbXhqYld4dFlWZE9hR1JIYkhaaWEzUnNaVlJKZDAxVVoybE1RMHAzWkZkS2MyRlhUa3hhV0d4SldsaG5hVTlwU1hkTk1sbDRUVWRPYkZsdFdUQlpha1V3VG1wQmVFMVVSWGxPYW1kNVdYcE9iVTVFVVhsTk1sVjRXVmRhYkU5WFNUQlpNa1YzV2xSTmVrMXFVWGhPYlVwdFdWUmpkMDVFVm1wT2VrSnBXa1JHYVU1SFNUVlpha1ZwWmxONE4wbHRiR3RKYW05cFNUTktiRmt5T1RKYVdFbzFTV2wzYVdSWVRtaGFNbFZwVDJsS2VWcFhUblprYlZaNVpWTkpjMGx1VWpWalIxVnBUMmxLVkZwWFRuZE5hbFV5WVhwR1YxcFlTbkJhYld4cVdWaFNjR0l5TlV4YVdHdDVUVVJGTkVscGQybGpTRlpwWWtkc2FsTXlWalZUUjFZMFNXcHZhVTFFVFRGTk1rMDFUMVJHYUU0eVdUUk5NbHBwV1ZkU2JWcHFVWGxaTWxac1QxUldiRnBxVVRST1IwbDNUMVJrYlU1VVJURmFWRXByV2tkVk1VMVVWWGRPYW14clRsUkJNbGxYVFhoTlZFazFUVVJhYUZsWFVUVkpiakZrWmxFaUxDSnphV2R1WVhSMWNtVWlPaUpVTVU1aVVpMVhhemRhWjNaTk5GWjJRVTlxTjB0SFpVOU9ZVWx4YTIxa1J6QkRkMVUyWDBOUVlqVkpXV3czYkRGNVZUQXhRbmh3VVZoemJVNURhV0l6Y2xCeFZFWlRhSFJGWHpKTVQyWmliMjFCV1U5VFVTSjkiXX1dfV0sImNhbGxiYWNrVVJMIjoiIn0sImV4cCI6MTYwMzEzMTkyMzgxNywidHlwIjoiY3JlZGVudGlhbFJlcXVlc3QiLCJqdGkiOiI4MWFhMzEwMzBkNjQ1YWYwIiwiaXNzIjoiZGlkOmVsZW06RWlCOVIwd2JRR3JMaTNwRWVIYnBROXVMcVZiSm5Va0UxMkRQaGcySEpHd2JqQTtlbGVtOmluaXRpYWwtc3RhdGU9ZXlKd2NtOTBaV04wWldRaU9pSmxlVXAyWTBkV2VWbFlVbkJpTWpScFQybEthbU50Vm1oa1IxVnBURU5LY21GWFVXbFBhVWxxWTBoS2NHSlhSbmxsVTBselNXMUdjMXA1U1RaSmExWlVUV3BWTWxONVNqa2lMQ0p3WVhsc2IyRmtJam9pWlhsS1FWa3lPWFZrUjFZMFpFTkpOa2x0YURCa1NFSjZUMms0ZG1SNlRuQmFRelYyWTIxamRtTXlWbXBrV0Vwd1pFaHJkbVJxU1dsTVEwcDNaRmRLYzJGWFRreGFXR3RwVDJ4ME4wbHRiR3RKYW05cFNUTkNlV0ZYTVdoamJtdHBURU5LTVdNeVJtNWFVMGsyU1c1T2NGb3lOWEJpYldOcFRFTktNR1ZZUW14SmFtOXBWVEpXYW1ORVNURk9iWE40Vm0xV2VXRlhXbkJaTWtZd1lWYzVkVk15VmpWTmFrRjRUME5KYzBsdVFqRlpiWGh3V1RCMGJHVlZhR3hsUTBrMlNXcEJlbHBxUlhkWk1sWnBXbXBTYVUxVVVUSk5SRVY0VFZSSk1rOUVTbXBOTWxrd1RrUkplbHBVUm1oYWJWVTFXV3BTYWxsVVFteE5lazE1VGtSRk1sbHRXbWhPZWtFd1RsZE5NMDFIU210TlYwa3dXV3BzYVUxVFNqbE1TSE5wWVZkUmFVOXBTV3BqYlZacVlqTmFiR051YTJsTVEwb3hZekpHYmxwVFNUWkpia3BzV1RJNU1scFlTalZKYVhkcFpFaHNkMXBUU1RaSmJFNXNXVE5CZVU1VVduSk5WbHBzWTIxc2JXRlhUbWhrUjJ4MlltdDBiR1ZVU1hkTlZHZHBURU5LZDJSWFNuTmhWMDVNV2xoc1NWcFlaMmxQYVVsM1RYcFZlbGw2YXpWTlYwVXpXbXBuZWxwdFNtaGFSMXB0VGtSS2FscFhWVFZPVjFadFRrUm5NRmxxUVRWT01sa3hUVlJXYkUxdFVtdGFWRlY0VGxSQk1rOVhVVEZOUkZwb1dYcEZlRTFxYTNkT2JVWm9Xa1JyYVdaV01ITkpiVVl4WkVkb2JHSnVVbkJaTWtZd1lWYzVkVWxxY0dKSmFVNTNZMjFzZEZsWVNqVkpiREJ6U1cxR2VtTXlWbmxrUjJ4Mlltc3hiR1JIYUhaYVEwazJWM2xKYW1OSVNuQmlWMFo1WlZOS1pHWlJJaXdpYzJsbmJtRjBkWEpsSWpvaWJuWk9UMTl4WWxKUGRqSlJhREJmZVY5ek1WWTRkRzVIWHpsamJYRlhaakpVU0RONWJ6TnRWRlZNV1RScVJYVnFWVVZHTW5GdU9YWkpiVXhpTW1aeWFHNW9NRWRxV2t0c09FWkZSSGN3YTNwVGRIUk1UR2NpZlEjcHJpbWFyeSJ9.64e3ac5723d78409890770baa2e98f1ccdfdd8b8b41a94c4720aa5b4d909911909df4c4815767bf5e0f9d3f1d98ef9efce982a228d81039989a3456aa0af3a14'
    const credentialShareResponseToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNhbGxiYWNrVVJMIjoiIiwic3VwcGxpZWRDcmVkZW50aWFscyI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLHsiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9OYW1lQ3JlZGVudGlhbFBlcnNvblYxIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZX19LCJkYXRhIjp7IkBpZCI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2RhdGEiLCJAY29udGV4dCI6W251bGwseyJAdmVyc2lvbiI6MS4xLCJAcHJvdGVjdGVkIjp0cnVlLCJAdm9jYWIiOiJodHRwczovL3NjaGVtYS5vcmcvIiwiTmFtZVBlcnNvbiI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9OYW1lUGVyc29uIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsIm5hbWUiOiJodHRwczovL3NjaGVtYS5vcmcvbmFtZSIsImdpdmVuTmFtZSI6Imh0dHBzOi8vc2NoZW1hLm9yZy9naXZlbk5hbWUiLCJmdWxsTmFtZSI6Imh0dHBzOi8vc2NoZW1hLm9yZy9mdWxsTmFtZSJ9fSwiUGVyc29uRSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9QZXJzb25FIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyJ9fSwiT3JnYW5pemF0aW9uRSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9Pcmdhbml6YXRpb25FIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsImhhc0NyZWRlbnRpYWwiOiJodHRwczovL3NjaGVtYS5vcmcvaGFzQ3JlZGVudGlhbCIsImluZHVzdHJ5IjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvaW5kdXN0cnkifX0sIkNyZWRlbnRpYWwiOnsiQGlkIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvQ3JlZGVudGlhbCIsIkBjb250ZXh0Ijp7IkB2ZXJzaW9uIjoxLjEsIkBwcm90ZWN0ZWQiOnRydWUsIkB2b2NhYiI6Imh0dHBzOi8vc2NoZW1hLm9yZy8iLCJkYXRlUmV2b2tlZCI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2RhdGVSZXZva2VkIiwicmVjb2duaXplZEJ5IjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvcmVjb2duaXplZEJ5In19LCJPcmdhbml6YXRpb25hbENyZWRlbnRpYWwiOnsiQGlkIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvT3JnYW5pemF0aW9uYWxDcmVkZW50aWFsIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsImNyZWRlbnRpYWxDYXRlZ29yeSI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2NyZWRlbnRpYWxDYXRlZ29yeSIsIm9yZ2FuaXphdGlvblR5cGUiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9vcmdhbml6YXRpb25UeXBlIiwiZ29vZFN0YW5kaW5nIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvZ29vZFN0YW5kaW5nIiwiYWN0aXZlIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvYWN0aXZlIiwicHJpbWFyeUp1cmlzZGljdGlvbiI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL3ByaW1hcnlKdXJpc2RpY3Rpb24iLCJpZGVudGlmaWVyIjoiaHR0cHM6Ly9zY2hlbWEub3JnL2lkZW50aWZpZXIifX19XX19XSwiaWQiOiJjbGFpbUlkOjYzYjVkMTFjMGQxYjU1NjYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSJdLCJob2xkZXIiOnsiaWQiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRhdGEiOnsiQHR5cGUiOlsiUGVyc29uIiwiUGVyc29uRSIsIk5hbWVQZXJzb24iXSwiZ2l2ZW5OYW1lIjoiRGVuaXNVcGRhdGVkIiwiZmFtaWx5TmFtZSI6IlBvcG92In19LCJpc3N1YW5jZURhdGUiOiIyMDIwLTAxLTE3VDA3OjA2OjM1LjQwM1oiLCJpc3N1ZXIiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSIsInByb29mIjp7InR5cGUiOiJFY2RzYVNlY3AyNTZrMVNpZ25hdHVyZTIwMTkiLCJjcmVhdGVkIjoiMjAyMC0xMC0xOVQxODoxNToyM1oiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBI3ByaW1hcnkiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJqd3MiOiJleUpoYkdjaU9pSkZVekkxTmtzaUxDSmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZGZRLi5zall0amhoOWpHM3lzMVZCd3BhMGJwY0JoV0t2dDU0NnIxdlYxX0U5YTIxdXUwOEFFVEI5MUZnLXBQN1F5eDVhVlU2N2hKTmt0c1RVR1FNbWxZLVE0USJ9fV19LCJleHAiOjI1MjQ2MTE2MDAwMDAsInR5cCI6ImNyZWRlbnRpYWxSZXNwb25zZSIsImp0aSI6IjgxYWEzMTAzMGQ2NDVhZjAiLCJhdWQiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSIsImlzcyI6ImRpZDplbGVtOkVpQjlSMHdiUUdyTGkzcEVlSGJwUTl1THFWYkpuVWtFMTJEUGhnMkhKR3diakE7ZWxlbTppbml0aWFsLXN0YXRlPWV5SndjbTkwWldOMFpXUWlPaUpsZVVwMlkwZFdlVmxZVW5CaU1qUnBUMmxLYW1OdFZtaGtSMVZwVEVOS2NtRlhVV2xQYVVscVkwaEtjR0pYUm5sbFUwbHpTVzFHYzFwNVNUWkphMVpVVFdwVk1sTjVTamtpTENKd1lYbHNiMkZrSWpvaVpYbEtRVmt5T1hWa1IxWTBaRU5KTmtsdGFEQmtTRUo2VDJrNGRtUjZUbkJhUXpWMlkyMWpkbU15Vm1wa1dFcHdaRWhyZG1ScVNXbE1RMHAzWkZkS2MyRlhUa3hhV0d0cFQyeDBOMGx0Ykd0SmFtOXBTVE5DZVdGWE1XaGpibXRwVEVOS01XTXlSbTVhVTBrMlNXNU9jRm95TlhCaWJXTnBURU5LTUdWWVFteEphbTlwVlRKV2FtTkVTVEZPYlhONFZtMVdlV0ZYV25CWk1rWXdZVmM1ZFZNeVZqVk5ha0Y0VDBOSmMwbHVRakZaYlhod1dUQjBiR1ZWYUd4bFEwazJTV3BCZWxwcVJYZFpNbFpwV21wU2FVMVVVVEpOUkVWNFRWUkpNazlFU21wTk1sa3dUa1JKZWxwVVJtaGFiVlUxV1dwU2FsbFVRbXhOZWsxNVRrUkZNbGx0V21oT2VrRXdUbGROTTAxSFNtdE5WMGt3V1dwc2FVMVRTamxNU0hOcFlWZFJhVTlwU1dwamJWWnFZak5hYkdOdWEybE1RMG94WXpKR2JscFRTVFpKYmtwc1dUSTVNbHBZU2pWSmFYZHBaRWhzZDFwVFNUWkpiRTVzV1ROQmVVNVVXbkpOVmxwc1kyMXNiV0ZYVG1oa1IyeDJZbXQwYkdWVVNYZE5WR2RwVEVOS2QyUlhTbk5oVjA1TVdsaHNTVnBZWjJsUGFVbDNUWHBWZWxsNmF6Vk5WMFV6V21wbmVscHRTbWhhUjFwdFRrUkthbHBYVlRWT1YxWnRUa1JuTUZscVFUVk9NbGt4VFZSV2JFMXRVbXRhVkZWNFRsUkJNazlYVVRGTlJGcG9XWHBGZUUxcWEzZE9iVVpvV2tScmFXWldNSE5KYlVZeFpFZG9iR0p1VW5CWk1rWXdZVmM1ZFVscWNHSkphVTUzWTIxc2RGbFlTalZKYkRCelNXMUdlbU15Vm5sa1IyeDJZbXN4YkdSSGFIWmFRMGsyVjNsSmFtTklTbkJpVjBaNVpWTktaR1pSSWl3aWMybG5ibUYwZFhKbElqb2liblpPVDE5eFlsSlBkakpSYURCZmVWOXpNVlk0ZEc1SFh6bGpiWEZYWmpKVVNETjViek50VkZWTVdUUnFSWFZxVlVWR01uRnVPWFpKYlV4aU1tWnlhRzVvTUVkcVdrdHNPRVpGUkhjd2EzcFRkSFJNVEdjaWZRI3ByaW1hcnkifQ.4db860fcb22fa9e887c4411ba5747e59f63e515e51aa240fc1543c532ea400d3162e7e58c6ec5e6f1446ad9e9af9936bc87e9002118cbf499ef7444ac7b6f607'

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)

    const pullFunction = () => {
      return credentialShareRequestToken
    }
    const { isValid, suppliedCredentials } = await commonNetworkMember.verifyCredentialShareResponseToken(
      credentialShareResponseToken,
      pullFunction,
      true,
    )

    expect(isValid).to.equal(true)
    expect(suppliedCredentials).to.exist
  })

  it('#verifyCredentialShareResponseToken function to pull request token passed and its not returned JWT', async () => {
    const credentialShareResponseToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNhbGxiYWNrVVJMIjoiaHR0cHM6Ly9rdWRvcy1pc3N1ZXItYmFja2VuZC5hZmZpbml0eS1wcm9qZWN0Lm9yZy9yZWNlaXZlL3Rlc3RlckJhZGdlIiwic3VwcGxpZWRDcmVkZW50aWFscyI6W3siQGNvbnRleHQiOlt7ImlkIjoiQGlkIiwidHlwZSI6IkB0eXBlIiwiY3JlZCI6Imh0dHBzOi8vdzNpZC5vcmcvY3JlZGVudGlhbHMjIiwic2NoZW1hIjoiaHR0cDovL3NjaGVtYS5vcmcvIiwiZGMiOiJodHRwOi8vcHVybC5vcmcvZGMvdGVybXMvIiwieHNkIjoiaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjIiwic2VjIjoiaHR0cHM6Ly93M2lkLm9yZy9zZWN1cml0eSMiLCJDcmVkZW50aWFsIjoiY3JlZDpDcmVkZW50aWFsIiwiaXNzdWVyIjp7IkBpZCI6ImNyZWQ6aXNzdWVyIiwiQHR5cGUiOiJAaWQifSwiaXNzdWVkIjp7IkBpZCI6ImNyZWQ6aXNzdWVkIiwiQHR5cGUiOiJ4c2Q6ZGF0ZVRpbWUifSwiY2xhaW0iOnsiQGlkIjoiY3JlZDpjbGFpbSIsIkB0eXBlIjoiQGlkIn0sImNyZWRlbnRpYWwiOnsiQGlkIjoiY3JlZDpjcmVkZW50aWFsIiwiQHR5cGUiOiJAaWQifSwiZXhwaXJlcyI6eyJAaWQiOiJzZWM6ZXhwaXJhdGlvbiIsIkB0eXBlIjoieHNkOmRhdGVUaW1lIn0sInByb29mIjp7IkBpZCI6InNlYzpwcm9vZiIsIkB0eXBlIjoiQGlkIn0sIkVjZHNhS29ibGl0elNpZ25hdHVyZTIwMTYiOiJzZWM6RWNkc2FLb2JsaXR6U2lnbmF0dXJlMjAxNiIsImNyZWF0ZWQiOnsiQGlkIjoiZGM6Y3JlYXRlZCIsIkB0eXBlIjoieHNkOmRhdGVUaW1lIn0sImNyZWF0b3IiOnsiQGlkIjoiZGM6Y3JlYXRvciIsIkB0eXBlIjoiQGlkIn0sImRvbWFpbiI6InNlYzpkb21haW4iLCJub25jZSI6InNlYzpub25jZSIsInNpZ25hdHVyZVZhbHVlIjoic2VjOnNpZ25hdHVyZVZhbHVlIn0seyJQcm9vZk9mTmFtZUNyZWRlbnRpYWwiOiJodHRwczovL2lkZW50aXR5LmpvbG9jb20uY29tL3Rlcm1zL1Byb29mT2ZOYW1lQ3JlZGVudGlhbCIsInNjaGVtYSI6Imh0dHA6Ly9zY2hlbWEub3JnLyIsImZhbWlseU5hbWUiOiJzY2hlbWE6ZmFtaWx5TmFtZSIsImdpdmVuTmFtZSI6InNjaGVtYTpnaXZlbk5hbWUifV0sImlkIjoiY2xhaW1JZDo2M2I1ZDExYzBkMWI1NTY2IiwiaXNzdWVyIjoiZGlkOmpvbG86NmRmNmZkNGE4NzZkY2QzNzVmYmM1ZDYzMGU2NGU3NTI5ZjI3ZTk2MTJhZWNiYmJmMzIxMzg2MWEyYjBiN2U5ZCIsImlzc3VlZCI6IjIwMjAtMDEtMTdUMDc6MDY6MzUuNDAzWiIsInR5cGUiOlsiQ3JlZGVudGlhbCIsIlByb29mT2ZOYW1lQ3JlZGVudGlhbCJdLCJleHBpcmVzIjoiMjAyMS0wMS0xNlQwNzowNjozNS4zMzdaIiwicHJvb2YiOnsiY3JlYXRlZCI6IjIwMjAtMDEtMTdUMDc6MDY6MzUuNDAyWiIsInR5cGUiOiJFY2RzYUtvYmxpdHpTaWduYXR1cmUyMDE2Iiwibm9uY2UiOiJjZjgyZjFiNDQ4NTE0MjI5Iiwic2lnbmF0dXJlVmFsdWUiOiI4NjYxOTFlYjNmN2E4NzFiNTlkMGM2NjVlZDhhNGMzYjc5OTEyNGFhNTRlOWZhZjdkMjE2MzQ4NmZkMTQ2YzE0MDQ3ZDNkNGE2ODgwNTZkNGM2ZDBhZDIyMTE3MGFmNTU1NjFkODdiODcyZTQyOGQzMGI1YzFmYThmZmQyN2Y4MyIsImNyZWF0b3IiOiJkaWQ6am9sbzo2ZGY2ZmQ0YTg3NmRjZDM3NWZiYzVkNjMwZTY0ZTc1MjlmMjdlOTYxMmFlY2JiYmYzMjEzODYxYTJiMGI3ZTlkI2tleXMtMSJ9LCJjbGFpbSI6eyJnaXZlbk5hbWUiOiJEZW5pc1VwZGF0ZWQiLCJmYW1pbHlOYW1lIjoiUG9wb3YiLCJpZCI6ImRpZDpqb2xvOjZkZjZmZDRhODc2ZGNkMzc1ZmJjNWQ2MzBlNjRlNzUyOWYyN2U5NjEyYWVjYmJiZjMyMTM4NjFhMmIwYjdlOWQifSwibmFtZSI6Ik5hbWUifV19LCJleHAiOjE2MjEwNzMxODc5OTIsInR5cCI6ImNyZWRlbnRpYWxSZXNwb25zZSIsImF1ZCI6ImRpZDpqb2xvOjhjMzExNzEzNWI2ODkyZjRlYTVkMDVlYzBjMjc3OGMzZGI0ZDkzZDRiMjRjNDk5MTYwODMxZWY5NzRhZGYzZWYiLCJqdGkiOiJhYTM3NmNjNzlkMGMzMjU5IiwiaXNzIjoiZGlkOmpvbG86NmRmNmZkNGE4NzZkY2QzNzVmYmM1ZDYzMGU2NGU3NTI5ZjI3ZTk2MTJhZWNiYmJmMzIxMzg2MWEyYjBiN2U5ZCNrZXlzLTEifQ.c483e3b589c82f96f65c8bd3e356979743968b965f01be1f2ca67b76283000065ba37893dd267d85d86adb60ae60fcd23ef1c06bd1efbceab5816bd261103b5b'

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    const pullFunction = () => {
      return ''
    }
    let validationError
    try {
      await commonNetworkMember.verifyCredentialShareResponseToken(credentialShareResponseToken, pullFunction)
    } catch (error) {
      validationError = error
    }

    expect(validationError).to.exist
    expect(validationError.code).to.be.equal('COR-15')
  })

  it('#verifyCredentialShareResponseToken throws `COR-1 / 400` when bad parameters passed', async () => {
    const credentialShareResponseToken = 123
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      await commonNetworkMember.verifyCredentialShareResponseToken(credentialShareResponseToken)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode } = responseError

    expect(code).to.equal('COR-1')
    expect(httpStatusCode).to.equal(400)
  })

  it('#verifyCredentialShareResponseToken throws `COR-19 / 400` when token is expired', async () => {
    const credentialShareResponseToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNhbGxiYWNrVVJMIjoiIiwic3VwcGxpZWRDcmVkZW50aWFscyI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLHsiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9OYW1lQ3JlZGVudGlhbFBlcnNvblYxIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZX19LCJkYXRhIjp7IkBpZCI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2RhdGEiLCJAY29udGV4dCI6W251bGwseyJAdmVyc2lvbiI6MS4xLCJAcHJvdGVjdGVkIjp0cnVlLCJAdm9jYWIiOiJodHRwczovL3NjaGVtYS5vcmcvIiwiTmFtZVBlcnNvbiI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9OYW1lUGVyc29uIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsIm5hbWUiOiJodHRwczovL3NjaGVtYS5vcmcvbmFtZSIsImdpdmVuTmFtZSI6Imh0dHBzOi8vc2NoZW1hLm9yZy9naXZlbk5hbWUiLCJmdWxsTmFtZSI6Imh0dHBzOi8vc2NoZW1hLm9yZy9mdWxsTmFtZSJ9fSwiUGVyc29uRSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9QZXJzb25FIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyJ9fSwiT3JnYW5pemF0aW9uRSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9Pcmdhbml6YXRpb25FIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsImhhc0NyZWRlbnRpYWwiOiJodHRwczovL3NjaGVtYS5vcmcvaGFzQ3JlZGVudGlhbCIsImluZHVzdHJ5IjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvaW5kdXN0cnkifX0sIkNyZWRlbnRpYWwiOnsiQGlkIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvQ3JlZGVudGlhbCIsIkBjb250ZXh0Ijp7IkB2ZXJzaW9uIjoxLjEsIkBwcm90ZWN0ZWQiOnRydWUsIkB2b2NhYiI6Imh0dHBzOi8vc2NoZW1hLm9yZy8iLCJkYXRlUmV2b2tlZCI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2RhdGVSZXZva2VkIiwicmVjb2duaXplZEJ5IjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvcmVjb2duaXplZEJ5In19LCJPcmdhbml6YXRpb25hbENyZWRlbnRpYWwiOnsiQGlkIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvT3JnYW5pemF0aW9uYWxDcmVkZW50aWFsIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsImNyZWRlbnRpYWxDYXRlZ29yeSI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2NyZWRlbnRpYWxDYXRlZ29yeSIsIm9yZ2FuaXphdGlvblR5cGUiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9vcmdhbml6YXRpb25UeXBlIiwiZ29vZFN0YW5kaW5nIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvZ29vZFN0YW5kaW5nIiwiYWN0aXZlIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvYWN0aXZlIiwicHJpbWFyeUp1cmlzZGljdGlvbiI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL3ByaW1hcnlKdXJpc2RpY3Rpb24iLCJpZGVudGlmaWVyIjoiaHR0cHM6Ly9zY2hlbWEub3JnL2lkZW50aWZpZXIifX19XX19XSwiaWQiOiJjbGFpbUlkOjYzYjVkMTFjMGQxYjU1NjYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSJdLCJob2xkZXIiOnsiaWQiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRhdGEiOnsiQHR5cGUiOlsiUGVyc29uIiwiUGVyc29uRSIsIk5hbWVQZXJzb24iXSwiZ2l2ZW5OYW1lIjoiRGVuaXNVcGRhdGVkIiwiZmFtaWx5TmFtZSI6IlBvcG92In19LCJpc3N1YW5jZURhdGUiOiIyMDIwLTAxLTE3VDA3OjA2OjM1LjQwM1oiLCJpc3N1ZXIiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSIsInByb29mIjp7InR5cGUiOiJFY2RzYVNlY3AyNTZrMVNpZ25hdHVyZTIwMTkiLCJjcmVhdGVkIjoiMjAyMC0xMC0xOVQxODowNzoxMVoiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBI3ByaW1hcnkiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJqd3MiOiJleUpoYkdjaU9pSkZVekkxTmtzaUxDSmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZGZRLi5MVXJmeGtEZjg2dHk5dmQwSzVQbG9uS3dwZFFYRlU2cXZlQ2xsS2dQM0JCc2ZNa3FQOTc3RVJHcVp1R3QxRjhxaFlBYzJVRHVMUEVNWDZZRHFNTWRCZyJ9fV19LCJleHAiOjE1NzkxODMzNjMwNjksInR5cCI6ImNyZWRlbnRpYWxSZXNwb25zZSIsImp0aSI6ImNlN2NjZDdkZjNjMDc2OTkiLCJhdWQiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSIsImlzcyI6ImRpZDplbGVtOkVpQjlSMHdiUUdyTGkzcEVlSGJwUTl1THFWYkpuVWtFMTJEUGhnMkhKR3diakE7ZWxlbTppbml0aWFsLXN0YXRlPWV5SndjbTkwWldOMFpXUWlPaUpsZVVwMlkwZFdlVmxZVW5CaU1qUnBUMmxLYW1OdFZtaGtSMVZwVEVOS2NtRlhVV2xQYVVscVkwaEtjR0pYUm5sbFUwbHpTVzFHYzFwNVNUWkphMVpVVFdwVk1sTjVTamtpTENKd1lYbHNiMkZrSWpvaVpYbEtRVmt5T1hWa1IxWTBaRU5KTmtsdGFEQmtTRUo2VDJrNGRtUjZUbkJhUXpWMlkyMWpkbU15Vm1wa1dFcHdaRWhyZG1ScVNXbE1RMHAzWkZkS2MyRlhUa3hhV0d0cFQyeDBOMGx0Ykd0SmFtOXBTVE5DZVdGWE1XaGpibXRwVEVOS01XTXlSbTVhVTBrMlNXNU9jRm95TlhCaWJXTnBURU5LTUdWWVFteEphbTlwVlRKV2FtTkVTVEZPYlhONFZtMVdlV0ZYV25CWk1rWXdZVmM1ZFZNeVZqVk5ha0Y0VDBOSmMwbHVRakZaYlhod1dUQjBiR1ZWYUd4bFEwazJTV3BCZWxwcVJYZFpNbFpwV21wU2FVMVVVVEpOUkVWNFRWUkpNazlFU21wTk1sa3dUa1JKZWxwVVJtaGFiVlUxV1dwU2FsbFVRbXhOZWsxNVRrUkZNbGx0V21oT2VrRXdUbGROTTAxSFNtdE5WMGt3V1dwc2FVMVRTamxNU0hOcFlWZFJhVTlwU1dwamJWWnFZak5hYkdOdWEybE1RMG94WXpKR2JscFRTVFpKYmtwc1dUSTVNbHBZU2pWSmFYZHBaRWhzZDFwVFNUWkpiRTVzV1ROQmVVNVVXbkpOVmxwc1kyMXNiV0ZYVG1oa1IyeDJZbXQwYkdWVVNYZE5WR2RwVEVOS2QyUlhTbk5oVjA1TVdsaHNTVnBZWjJsUGFVbDNUWHBWZWxsNmF6Vk5WMFV6V21wbmVscHRTbWhhUjFwdFRrUkthbHBYVlRWT1YxWnRUa1JuTUZscVFUVk9NbGt4VFZSV2JFMXRVbXRhVkZWNFRsUkJNazlYVVRGTlJGcG9XWHBGZUUxcWEzZE9iVVpvV2tScmFXWldNSE5KYlVZeFpFZG9iR0p1VW5CWk1rWXdZVmM1ZFVscWNHSkphVTUzWTIxc2RGbFlTalZKYkRCelNXMUdlbU15Vm5sa1IyeDJZbXN4YkdSSGFIWmFRMGsyVjNsSmFtTklTbkJpVjBaNVpWTktaR1pSSWl3aWMybG5ibUYwZFhKbElqb2liblpPVDE5eFlsSlBkakpSYURCZmVWOXpNVlk0ZEc1SFh6bGpiWEZYWmpKVVNETjViek50VkZWTVdUUnFSWFZxVlVWR01uRnVPWFpKYlV4aU1tWnlhRzVvTUVkcVdrdHNPRVpGUkhjd2EzcFRkSFJNVEdjaWZRI3ByaW1hcnkifQ.a1b0a6a2385f99c08728391bd5822b176287c07bcab4c65dc56fc91dd88901214bf41e2836e27ebac4f8c23c6a42d7248514a3485ec8b2437660cb82b181c8a0'
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.verifyCredentialShareResponseToken(credentialShareResponseToken)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode, message } = responseError

    expect(code).to.equal('COR-19')
    expect(message).to.equal('Token expired')
    expect(httpStatusCode).to.equal(400)
  })

  // TODO: need here update request/response token, response token should be generated with exp in several years
  it.skip('#verifyCredentialShareResponseToken throws `COM-0 / 500` when issuer did does not exist on the ledger', async () => {
    const credentialShareRequestToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNyZWRlbnRpYWxSZXF1aXJlbWVudHMiOlt7InR5cGUiOlsiQ3JlZGVudGlhbCIsIlByb29mT2ZOYW1lQ3JlZGVudGlhbCJdLCJjb25zdHJhaW50cyI6W119XSwiY2FsbGJhY2tVUkwiOiJodHRwczovL2t1ZG9zLWlzc3Vlci1iYWNrZW5kLmFmZmluaXR5LXByb2plY3Qub3JnL3JlY2VpdmUvdGVzdGVyQmFkZ2UifSwiZXhwIjoxNTg5NTM1Mjk3NDI4LCJ0eXAiOiJjcmVkZW50aWFsUmVxdWVzdCIsImp0aSI6IjcwNDU2YTFjOTMyODYzOWEiLCJpc3MiOiJkaWQ6am9sbzo5MTA0Njg1NmIwMjhmYjUyNDMzZjZkZWY2MTcwOWI1YzEyYWMxMzBjNDUwYjJjN2I1Y2I0ZThjM2ZjZjM3NjRhI2tleXMtMSJ9.cf89170160c02f2158e5cf8c80f28488fe291a4373e1dcc5edcaa97896ee678039303c3077f4a5d30b01b89f373c98fa11b6f938261d5495ceee3845c7359fc2'
    const credentialShareResponseToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNhbGxiYWNrVVJMIjoiaHR0cHM6Ly9rdWRvcy1pc3N1ZXItYmFja2VuZC5hZmZpbml0eS1wcm9qZWN0Lm9yZy9yZWNlaXZlL3Rlc3RlckJhZGdlIiwic3VwcGxpZWRDcmVkZW50aWFscyI6W3siQGNvbnRleHQiOlt7ImlkIjoiQGlkIiwidHlwZSI6IkB0eXBlIiwiY3JlZCI6Imh0dHBzOi8vdzNpZC5vcmcvY3JlZGVudGlhbHMjIiwic2NoZW1hIjoiaHR0cDovL3NjaGVtYS5vcmcvIiwiZGMiOiJodHRwOi8vcHVybC5vcmcvZGMvdGVybXMvIiwieHNkIjoiaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjIiwic2VjIjoiaHR0cHM6Ly93M2lkLm9yZy9zZWN1cml0eSMiLCJDcmVkZW50aWFsIjoiY3JlZDpDcmVkZW50aWFsIiwiaXNzdWVyIjp7IkBpZCI6ImNyZWQ6aXNzdWVyIiwiQHR5cGUiOiJAaWQifSwiaXNzdWVkIjp7IkBpZCI6ImNyZWQ6aXNzdWVkIiwiQHR5cGUiOiJ4c2Q6ZGF0ZVRpbWUifSwiY2xhaW0iOnsiQGlkIjoiY3JlZDpjbGFpbSIsIkB0eXBlIjoiQGlkIn0sImNyZWRlbnRpYWwiOnsiQGlkIjoiY3JlZDpjcmVkZW50aWFsIiwiQHR5cGUiOiJAaWQifSwiZXhwaXJlcyI6eyJAaWQiOiJzZWM6ZXhwaXJhdGlvbiIsIkB0eXBlIjoieHNkOmRhdGVUaW1lIn0sInByb29mIjp7IkBpZCI6InNlYzpwcm9vZiIsIkB0eXBlIjoiQGlkIn0sIkVjZHNhS29ibGl0elNpZ25hdHVyZTIwMTYiOiJzZWM6RWNkc2FLb2JsaXR6U2lnbmF0dXJlMjAxNiIsImNyZWF0ZWQiOnsiQGlkIjoiZGM6Y3JlYXRlZCIsIkB0eXBlIjoieHNkOmRhdGVUaW1lIn0sImNyZWF0b3IiOnsiQGlkIjoiZGM6Y3JlYXRvciIsIkB0eXBlIjoiQGlkIn0sImRvbWFpbiI6InNlYzpkb21haW4iLCJub25jZSI6InNlYzpub25jZSIsInNpZ25hdHVyZVZhbHVlIjoic2VjOnNpZ25hdHVyZVZhbHVlIn0seyJQcm9vZk9mTmFtZUNyZWRlbnRpYWwiOiJodHRwczovL2lkZW50aXR5LmpvbG9jb20uY29tL3Rlcm1zL1Byb29mT2ZOYW1lQ3JlZGVudGlhbCIsInNjaGVtYSI6Imh0dHA6Ly9zY2hlbWEub3JnLyIsImZhbWlseU5hbWUiOiJzY2hlbWE6ZmFtaWx5TmFtZSIsImdpdmVuTmFtZSI6InNjaGVtYTpnaXZlbk5hbWUifV0sImlkIjoiY2xhaW1JZDo2M2I1ZDExYzBkMWI1NTY2IiwiaXNzdWVyIjoiZGlkOmpvbG86NmRmNmZkNGE4NzZkY2QzNzVmYmM1ZDYzMGU2NGU3NTI5ZjI3ZTk2MTJhZWNiYmJmMzIxMzg2MWEyYjBiN2U5ZCIsImlzc3VlZCI6IjIwMjAtMDEtMTdUMDc6MDY6MzUuNDAzWiIsInR5cGUiOlsiQ3JlZGVudGlhbCIsIlByb29mT2ZOYW1lQ3JlZGVudGlhbCJdLCJleHBpcmVzIjoiMjAyMS0wMS0xNlQwNzowNjozNS4zMzdaIiwicHJvb2YiOnsiY3JlYXRlZCI6IjIwMjAtMDEtMTdUMDc6MDY6MzUuNDAyWiIsInR5cGUiOiJFY2RzYUtvYmxpdHpTaWduYXR1cmUyMDE2Iiwibm9uY2UiOiJjZjgyZjFiNDQ4NTE0MjI5Iiwic2lnbmF0dXJlVmFsdWUiOiI4NjYxOTFlYjNmN2E4NzFiNTlkMGM2NjVlZDhhNGMzYjc5OTEyNGFhNTRlOWZhZjdkMjE2MzQ4NmZkMTQ2YzE0MDQ3ZDNkNGE2ODgwNTZkNGM2ZDBhZDIyMTE3MGFmNTU1NjFkODdiODcyZTQyOGQzMGI1YzFmYThmZmQyN2Y4MyIsImNyZWF0b3IiOiJkaWQ6am9sbzo2ZGY2ZmQ0YTg3NmRjZDM3NWZiYzVkNjMwZTY0ZTc1MjlmMjdlOTYxMmFlY2JiYmYzMjEzODYxYTJiMGI3ZTlkI2tleXMtMSJ9LCJjbGFpbSI6eyJnaXZlbk5hbWUiOiJEZW5pc1VwZGF0ZWQiLCJmYW1pbHlOYW1lIjoiUG9wb3YiLCJpZCI6ImRpZDpqb2xvOjZkZjZmZDRhODc2ZGNkMzc1ZmJjNWQ2MzBlNjRlNzUyOWYyN2U5NjEyYWVjYmJiZjMyMTM4NjFhMmIwYjdlOWQifSwibmFtZSI6Ik5hbWUifV19LCJleHAiOjE1ODk1MzUyOTgxMzIsInR5cCI6ImNyZWRlbnRpYWxSZXNwb25zZSIsImF1ZCI6ImRpZDpqb2xvOjkxMDQ2ODU2YjAyOGZiNTI0MzNmNmRlZjYxNzA5YjVjMTJhYzEzMGM0NTBiMmM3YjVjYjRlOGMzZmNmMzc2NGEiLCJqdGkiOiI3MDQ1NmExYzkzMjg2MzlhIiwiaXNzIjoiZGlkOmVsZW06RWlEVll1SzR1YklMYjdXdUUtWkt2RVRlU0ZqZ2F1Nm1WenE3Sm5zTmJwVUQ4ZztlbGVtOmluaXRpYWwtc3RhdGU9ZXlKd2NtOTBaV04wWldRaU9pSmxlVXAyWTBkV2VWbFlVbkJpTWpScFQybEthbU50Vm1oa1IxVnBURU5LY21GWFVXbFBhVWxxWTBoS2NHSlhSbmxsVTBselNXMUdjMXA1U1RaSmExWlVUV3BWTWxONVNqa2lMQ0p3WVhsc2IyRmtJam9pWlhsS1FWa3lPWFZrUjFZMFpFTkpOa2x0YURCa1NFSjZUMms0ZG1SNlRuQmFRelYyWTIxamRscEhiR3RNTTFsNFNXbDNhV05JVm1saVIyeHFVekpXTlVscWNHSmxlVXB3V2tOSk5rbHBUbmRqYld4MFdWaEtOVWxwZDJsa1dFNW9XakpWYVU5cFNucGhWMlIxWVZjMWJrbHBkMmxrU0d4M1dsTkpOa2xzVG14Wk0wRjVUbFJhY2sxV1dteGpiV3h0WVZkT2FHUkhiSFppYTNSc1pWUkpkMDFVWjJsTVEwcDNaRmRLYzJGWFRreGFXR3hKV2xobmFVOXBTWGROYW1ob1RUSkdhazVFWXpWTlZHY3lUa1JDYUU1dFJYZGFSRkUxV1ZkS2FVMVVUWGxhYlZGM1RXMU9hRnBVVFhoT2VsVjNXbGRPYVUxWFZUTk9lbHBvV1cxVmVVNVVUWGxhYWtacFQxZFpOVmw2YXpCT2FtdHBabE40TjBsdGJHdEphbTlwU1ROS2JGa3lPVEphV0VvMVNXbDNhV1JZVG1oYU1sVnBUMmxLZVZwWFRuWmtiVlo1WlZOSmMwbHVValZqUjFWcFQybEtWRnBYVG5kTmFsVXlZWHBHVjFwWVNuQmFiV3hxV1ZoU2NHSXlOVXhhV0d0NVRVUkZORWxwZDJsalNGWnBZa2RzYWxNeVZqVlRSMVkwU1dwdmFVMUVUbXhOTWxFeFRtcGpORmxxWjNkTmVtaHJXbXBqTlZreVNteE9lbVJvV1RKVk1rNXFRbWxaYWtwc1dXMUZNMDlFWXpKTlIxVjRUVVJyTUZwRVVYbFpNa1pwVGpKS2FrMUVhelZOUkZrMVRqSlZlVTVxWnpGSmJqRmtabEVpTENKemFXZHVZWFIxY21VaU9pSllWSEF6ZGxNemRHTlZYMUpHUlRGdWFtdFVaVlI0UmpsWGJtMXVTa2w0ZFRFd2VuRjBNemxpTXkxbmQwWnlkREZJZVdoeFkzUTJUV1l5U25kNlRtVmZRWGx6VVdoSmNXWk5iMWhLVFVvd1MyOWhZVTFvVVNKOSNwcmltYXJ5In0.56419bf1583f66e89f8c544c39b6b76bd5f873019d926ad189e67d0c16932aa62102be9b8000e533e1db71274a40e49ab73ead94b979da766ba1cf54bd73d236'

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.verifyCredentialShareResponseToken(
        credentialShareResponseToken,
        credentialShareRequestToken,
        true,
      )
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode, message } = responseError

    expect(code).to.equal('COM-0')
    expect(message).to.equal('DID of this token issuer does not exists at the ledger')
    expect(httpStatusCode).to.equal(500)
  })

  it('#verifyCredentialShareResponseToken when holder must be a subject', async () => {
    const credentialShareRequestToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNyZWRlbnRpYWxSZXF1aXJlbWVudHMiOlt7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJOYW1lQ3JlZGVudGlhbFBlcnNvblYxIl0sImNvbnN0cmFpbnRzIjpbeyI9PSI6W3sidmFyIjoiaXNzdWVyIn0sImRpZDplbGVtOkVpQmJmRXJyZ3FTU3ZBa19sM2pESXhXcUhhRWJDQUlKT2Uxb2JLMHB5ZmpqUnc7ZWxlbTppbml0aWFsLXN0YXRlPWV5SndjbTkwWldOMFpXUWlPaUpsZVVwMlkwZFdlVmxZVW5CaU1qUnBUMmxLYW1OdFZtaGtSMVZwVEVOS2NtRlhVV2xQYVVscVkwaEtjR0pYUm5sbFUwbHpTVzFHYzFwNVNUWkphMVpVVFdwVk1sTjVTamtpTENKd1lYbHNiMkZrSWpvaVpYbEtRVmt5T1hWa1IxWTBaRU5KTmtsdGFEQmtTRUo2VDJrNGRtUjZUbkJhUXpWMlkyMWpkbHBIYkd0TU0xbDRTV2wzYVdOSVZtbGlSMnhxVXpKV05VbHFjR0psZVVwd1drTkpOa2xwVG5kamJXeDBXVmhLTlVscGQybGtXRTVvV2pKVmFVOXBTbnBoVjJSMVlWYzFia2xwZDJsa1NHeDNXbE5KTmtsc1RteFpNMEY1VGxSYWNrMVdXbXhqYld4dFlWZE9hR1JIYkhaaWEzUnNaVlJKZDAxVVoybE1RMHAzWkZkS2MyRlhUa3hhV0d4SldsaG5hVTlwU1hkTk1sbDRUVWRPYkZsdFdUQlpha1V3VG1wQmVFMVVSWGxPYW1kNVdYcE9iVTVFVVhsTk1sVjRXVmRhYkU5WFNUQlpNa1YzV2xSTmVrMXFVWGhPYlVwdFdWUmpkMDVFVm1wT2VrSnBXa1JHYVU1SFNUVlpha1ZwWmxONE4wbHRiR3RKYW05cFNUTktiRmt5T1RKYVdFbzFTV2wzYVdSWVRtaGFNbFZwVDJsS2VWcFhUblprYlZaNVpWTkpjMGx1VWpWalIxVnBUMmxLVkZwWFRuZE5hbFV5WVhwR1YxcFlTbkJhYld4cVdWaFNjR0l5TlV4YVdHdDVUVVJGTkVscGQybGpTRlpwWWtkc2FsTXlWalZUUjFZMFNXcHZhVTFFVFRGTk1rMDFUMVJHYUU0eVdUUk5NbHBwV1ZkU2JWcHFVWGxaTWxac1QxUldiRnBxVVRST1IwbDNUMVJrYlU1VVJURmFWRXByV2tkVk1VMVVWWGRPYW14clRsUkJNbGxYVFhoTlZFazFUVVJhYUZsWFVUVkpiakZrWmxFaUxDSnphV2R1WVhSMWNtVWlPaUpVTVU1aVVpMVhhemRhWjNaTk5GWjJRVTlxTjB0SFpVOU9ZVWx4YTIxa1J6QkRkMVUyWDBOUVlqVkpXV3czYkRGNVZUQXhRbmh3VVZoemJVNURhV0l6Y2xCeFZFWlRhSFJGWHpKTVQyWmliMjFCV1U5VFVTSjkiXX1dfV0sImNhbGxiYWNrVVJMIjoiIn0sImV4cCI6MTYwMzEzMTkyMzgxNywidHlwIjoiY3JlZGVudGlhbFJlcXVlc3QiLCJqdGkiOiI4MWFhMzEwMzBkNjQ1YWYwIiwiaXNzIjoiZGlkOmVsZW06RWlCOVIwd2JRR3JMaTNwRWVIYnBROXVMcVZiSm5Va0UxMkRQaGcySEpHd2JqQTtlbGVtOmluaXRpYWwtc3RhdGU9ZXlKd2NtOTBaV04wWldRaU9pSmxlVXAyWTBkV2VWbFlVbkJpTWpScFQybEthbU50Vm1oa1IxVnBURU5LY21GWFVXbFBhVWxxWTBoS2NHSlhSbmxsVTBselNXMUdjMXA1U1RaSmExWlVUV3BWTWxONVNqa2lMQ0p3WVhsc2IyRmtJam9pWlhsS1FWa3lPWFZrUjFZMFpFTkpOa2x0YURCa1NFSjZUMms0ZG1SNlRuQmFRelYyWTIxamRtTXlWbXBrV0Vwd1pFaHJkbVJxU1dsTVEwcDNaRmRLYzJGWFRreGFXR3RwVDJ4ME4wbHRiR3RKYW05cFNUTkNlV0ZYTVdoamJtdHBURU5LTVdNeVJtNWFVMGsyU1c1T2NGb3lOWEJpYldOcFRFTktNR1ZZUW14SmFtOXBWVEpXYW1ORVNURk9iWE40Vm0xV2VXRlhXbkJaTWtZd1lWYzVkVk15VmpWTmFrRjRUME5KYzBsdVFqRlpiWGh3V1RCMGJHVlZhR3hsUTBrMlNXcEJlbHBxUlhkWk1sWnBXbXBTYVUxVVVUSk5SRVY0VFZSSk1rOUVTbXBOTWxrd1RrUkplbHBVUm1oYWJWVTFXV3BTYWxsVVFteE5lazE1VGtSRk1sbHRXbWhPZWtFd1RsZE5NMDFIU210TlYwa3dXV3BzYVUxVFNqbE1TSE5wWVZkUmFVOXBTV3BqYlZacVlqTmFiR051YTJsTVEwb3hZekpHYmxwVFNUWkpia3BzV1RJNU1scFlTalZKYVhkcFpFaHNkMXBUU1RaSmJFNXNXVE5CZVU1VVduSk5WbHBzWTIxc2JXRlhUbWhrUjJ4MlltdDBiR1ZVU1hkTlZHZHBURU5LZDJSWFNuTmhWMDVNV2xoc1NWcFlaMmxQYVVsM1RYcFZlbGw2YXpWTlYwVXpXbXBuZWxwdFNtaGFSMXB0VGtSS2FscFhWVFZPVjFadFRrUm5NRmxxUVRWT01sa3hUVlJXYkUxdFVtdGFWRlY0VGxSQk1rOVhVVEZOUkZwb1dYcEZlRTFxYTNkT2JVWm9Xa1JyYVdaV01ITkpiVVl4WkVkb2JHSnVVbkJaTWtZd1lWYzVkVWxxY0dKSmFVNTNZMjFzZEZsWVNqVkpiREJ6U1cxR2VtTXlWbmxrUjJ4Mlltc3hiR1JIYUhaYVEwazJWM2xKYW1OSVNuQmlWMFo1WlZOS1pHWlJJaXdpYzJsbmJtRjBkWEpsSWpvaWJuWk9UMTl4WWxKUGRqSlJhREJmZVY5ek1WWTRkRzVIWHpsamJYRlhaakpVU0RONWJ6TnRWRlZNV1RScVJYVnFWVVZHTW5GdU9YWkpiVXhpTW1aeWFHNW9NRWRxV2t0c09FWkZSSGN3YTNwVGRIUk1UR2NpZlEjcHJpbWFyeSJ9.64e3ac5723d78409890770baa2e98f1ccdfdd8b8b41a94c4720aa5b4d909911909df4c4815767bf5e0f9d3f1d98ef9efce982a228d81039989a3456aa0af3a14'
    const credentialShareResponseToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNhbGxiYWNrVVJMIjoiIiwic3VwcGxpZWRDcmVkZW50aWFscyI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLHsiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9OYW1lQ3JlZGVudGlhbFBlcnNvblYxIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZX19LCJkYXRhIjp7IkBpZCI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2RhdGEiLCJAY29udGV4dCI6W251bGwseyJAdmVyc2lvbiI6MS4xLCJAcHJvdGVjdGVkIjp0cnVlLCJAdm9jYWIiOiJodHRwczovL3NjaGVtYS5vcmcvIiwiTmFtZVBlcnNvbiI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9OYW1lUGVyc29uIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsIm5hbWUiOiJodHRwczovL3NjaGVtYS5vcmcvbmFtZSIsImdpdmVuTmFtZSI6Imh0dHBzOi8vc2NoZW1hLm9yZy9naXZlbk5hbWUiLCJmdWxsTmFtZSI6Imh0dHBzOi8vc2NoZW1hLm9yZy9mdWxsTmFtZSJ9fSwiUGVyc29uRSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9QZXJzb25FIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyJ9fSwiT3JnYW5pemF0aW9uRSI6eyJAaWQiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9Pcmdhbml6YXRpb25FIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsImhhc0NyZWRlbnRpYWwiOiJodHRwczovL3NjaGVtYS5vcmcvaGFzQ3JlZGVudGlhbCIsImluZHVzdHJ5IjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvaW5kdXN0cnkifX0sIkNyZWRlbnRpYWwiOnsiQGlkIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvQ3JlZGVudGlhbCIsIkBjb250ZXh0Ijp7IkB2ZXJzaW9uIjoxLjEsIkBwcm90ZWN0ZWQiOnRydWUsIkB2b2NhYiI6Imh0dHBzOi8vc2NoZW1hLm9yZy8iLCJkYXRlUmV2b2tlZCI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2RhdGVSZXZva2VkIiwicmVjb2duaXplZEJ5IjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvcmVjb2duaXplZEJ5In19LCJPcmdhbml6YXRpb25hbENyZWRlbnRpYWwiOnsiQGlkIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvT3JnYW5pemF0aW9uYWxDcmVkZW50aWFsIiwiQGNvbnRleHQiOnsiQHZlcnNpb24iOjEuMSwiQHByb3RlY3RlZCI6dHJ1ZSwiQHZvY2FiIjoiaHR0cHM6Ly9zY2hlbWEub3JnLyIsImNyZWRlbnRpYWxDYXRlZ29yeSI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL2NyZWRlbnRpYWxDYXRlZ29yeSIsIm9yZ2FuaXphdGlvblR5cGUiOiJodHRwczovL3NjaGVtYS5hZmZpbml0eS1wcm9qZWN0Lm9yZy9vcmdhbml6YXRpb25UeXBlIiwiZ29vZFN0YW5kaW5nIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvZ29vZFN0YW5kaW5nIiwiYWN0aXZlIjoiaHR0cHM6Ly9zY2hlbWEuYWZmaW5pdHktcHJvamVjdC5vcmcvYWN0aXZlIiwicHJpbWFyeUp1cmlzZGljdGlvbiI6Imh0dHBzOi8vc2NoZW1hLmFmZmluaXR5LXByb2plY3Qub3JnL3ByaW1hcnlKdXJpc2RpY3Rpb24iLCJpZGVudGlmaWVyIjoiaHR0cHM6Ly9zY2hlbWEub3JnL2lkZW50aWZpZXIifX19XX19XSwiaWQiOiJjbGFpbUlkOjYzYjVkMTFjMGQxYjU1NjYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSJdLCJob2xkZXIiOnsiaWQiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRhdGEiOnsiQHR5cGUiOlsiUGVyc29uIiwiUGVyc29uRSIsIk5hbWVQZXJzb24iXSwiZ2l2ZW5OYW1lIjoiRGVuaXNVcGRhdGVkIiwiZmFtaWx5TmFtZSI6IlBvcG92In19LCJpc3N1YW5jZURhdGUiOiIyMDIwLTAxLTE3VDA3OjA2OjM1LjQwM1oiLCJpc3N1ZXIiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSIsInByb29mIjp7InR5cGUiOiJFY2RzYVNlY3AyNTZrMVNpZ25hdHVyZTIwMTkiLCJjcmVhdGVkIjoiMjAyMC0xMC0xOVQxODoxNToyM1oiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBI3ByaW1hcnkiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJqd3MiOiJleUpoYkdjaU9pSkZVekkxTmtzaUxDSmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZGZRLi5zall0amhoOWpHM3lzMVZCd3BhMGJwY0JoV0t2dDU0NnIxdlYxX0U5YTIxdXUwOEFFVEI5MUZnLXBQN1F5eDVhVlU2N2hKTmt0c1RVR1FNbWxZLVE0USJ9fV19LCJleHAiOjI1MjQ2MTE2MDAwMDAsInR5cCI6ImNyZWRlbnRpYWxSZXNwb25zZSIsImp0aSI6IjgxYWEzMTAzMGQ2NDVhZjAiLCJhdWQiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSIsImlzcyI6ImRpZDplbGVtOkVpQjlSMHdiUUdyTGkzcEVlSGJwUTl1THFWYkpuVWtFMTJEUGhnMkhKR3diakE7ZWxlbTppbml0aWFsLXN0YXRlPWV5SndjbTkwWldOMFpXUWlPaUpsZVVwMlkwZFdlVmxZVW5CaU1qUnBUMmxLYW1OdFZtaGtSMVZwVEVOS2NtRlhVV2xQYVVscVkwaEtjR0pYUm5sbFUwbHpTVzFHYzFwNVNUWkphMVpVVFdwVk1sTjVTamtpTENKd1lYbHNiMkZrSWpvaVpYbEtRVmt5T1hWa1IxWTBaRU5KTmtsdGFEQmtTRUo2VDJrNGRtUjZUbkJhUXpWMlkyMWpkbU15Vm1wa1dFcHdaRWhyZG1ScVNXbE1RMHAzWkZkS2MyRlhUa3hhV0d0cFQyeDBOMGx0Ykd0SmFtOXBTVE5DZVdGWE1XaGpibXRwVEVOS01XTXlSbTVhVTBrMlNXNU9jRm95TlhCaWJXTnBURU5LTUdWWVFteEphbTlwVlRKV2FtTkVTVEZPYlhONFZtMVdlV0ZYV25CWk1rWXdZVmM1ZFZNeVZqVk5ha0Y0VDBOSmMwbHVRakZaYlhod1dUQjBiR1ZWYUd4bFEwazJTV3BCZWxwcVJYZFpNbFpwV21wU2FVMVVVVEpOUkVWNFRWUkpNazlFU21wTk1sa3dUa1JKZWxwVVJtaGFiVlUxV1dwU2FsbFVRbXhOZWsxNVRrUkZNbGx0V21oT2VrRXdUbGROTTAxSFNtdE5WMGt3V1dwc2FVMVRTamxNU0hOcFlWZFJhVTlwU1dwamJWWnFZak5hYkdOdWEybE1RMG94WXpKR2JscFRTVFpKYmtwc1dUSTVNbHBZU2pWSmFYZHBaRWhzZDFwVFNUWkpiRTVzV1ROQmVVNVVXbkpOVmxwc1kyMXNiV0ZYVG1oa1IyeDJZbXQwYkdWVVNYZE5WR2RwVEVOS2QyUlhTbk5oVjA1TVdsaHNTVnBZWjJsUGFVbDNUWHBWZWxsNmF6Vk5WMFV6V21wbmVscHRTbWhhUjFwdFRrUkthbHBYVlRWT1YxWnRUa1JuTUZscVFUVk9NbGt4VFZSV2JFMXRVbXRhVkZWNFRsUkJNazlYVVRGTlJGcG9XWHBGZUUxcWEzZE9iVVpvV2tScmFXWldNSE5KYlVZeFpFZG9iR0p1VW5CWk1rWXdZVmM1ZFVscWNHSkphVTUzWTIxc2RGbFlTalZKYkRCelNXMUdlbU15Vm5sa1IyeDJZbXN4YkdSSGFIWmFRMGsyVjNsSmFtTklTbkJpVjBaNVpWTktaR1pSSWl3aWMybG5ibUYwZFhKbElqb2liblpPVDE5eFlsSlBkakpSYURCZmVWOXpNVlk0ZEc1SFh6bGpiWEZYWmpKVVNETjViek50VkZWTVdUUnFSWFZxVlVWR01uRnVPWFpKYlV4aU1tWnlhRzVvTUVkcVdrdHNPRVpGUkhjd2EzcFRkSFJNVEdjaWZRI3ByaW1hcnkifQ.4db860fcb22fa9e887c4411ba5747e59f63e515e51aa240fc1543c532ea400d3162e7e58c6ec5e6f1446ad9e9af9936bc87e9002118cbf499ef7444ac7b6f607'

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)

    const { isValid, suppliedCredentials } = await commonNetworkMember.verifyCredentialShareResponseToken(
      credentialShareResponseToken,
      credentialShareRequestToken,
      true,
    )

    expect(isValid).to.equal(true)
    expect(suppliedCredentials).to.exist
  })

  it('#verifyCredentialOfferResponseToken', async () => {
    const credentialOfferRequestToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNhbGxiYWNrVVJMIjoiIiwib2ZmZXJlZENyZWRlbnRpYWxzIjpbeyJ0eXBlIjoiTmFtZUNyZWRlbnRpYWxQZXJzb25WMSJ9XX0sImV4cCI6MTYwMzEzMzgzOTMzOSwidHlwIjoiY3JlZGVudGlhbE9mZmVyUmVxdWVzdCIsImp0aSI6ImFiYTM5MWM4MzgzMWZjOTUiLCJpc3MiOiJkaWQ6ZWxlbTpFaUI5UjB3YlFHckxpM3BFZUhicFE5dUxxVmJKblVrRTEyRFBoZzJISkd3YmpBO2VsZW06aW5pdGlhbC1zdGF0ZT1leUp3Y205MFpXTjBaV1FpT2lKbGVVcDJZMGRXZVZsWVVuQmlNalJwVDJsS2FtTnRWbWhrUjFWcFRFTktjbUZYVVdsUGFVbHFZMGhLY0dKWFJubGxVMGx6U1cxR2MxcDVTVFpKYTFaVVRXcFZNbE41U2praUxDSndZWGxzYjJGa0lqb2laWGxLUVZreU9YVmtSMVkwWkVOSk5rbHRhREJrU0VKNlQyazRkbVI2VG5CYVF6VjJZMjFqZG1NeVZtcGtXRXB3WkVocmRtUnFTV2xNUTBwM1pGZEtjMkZYVGt4YVdHdHBUMngwTjBsdGJHdEphbTlwU1ROQ2VXRlhNV2hqYm10cFRFTktNV015Um01YVUwazJTVzVPY0ZveU5YQmliV05wVEVOS01HVllRbXhKYW05cFZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQwTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmFHeGxRMGsyU1dwQmVscHFSWGRaTWxacFdtcFNhVTFVVVRKTlJFVjRUVlJKTWs5RVNtcE5NbGt3VGtSSmVscFVSbWhhYlZVMVdXcFNhbGxVUW14TmVrMTVUa1JGTWxsdFdtaE9la0V3VGxkTk0wMUhTbXROVjBrd1dXcHNhVTFUU2psTVNITnBZVmRSYVU5cFNXcGpiVlpxWWpOYWJHTnVhMmxNUTBveFl6SkdibHBUU1RaSmJrcHNXVEk1TWxwWVNqVkphWGRwWkVoc2QxcFRTVFpKYkU1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkdkcFRFTktkMlJYU25OaFYwNU1XbGhzU1ZwWVoybFBhVWwzVFhwVmVsbDZhelZOVjBVeldtcG5lbHB0U21oYVIxcHRUa1JLYWxwWFZUVk9WMVp0VGtSbk1GbHFRVFZPTWxreFRWUldiRTF0VW10YVZGVjRUbFJCTWs5WFVURk5SRnBvV1hwRmVFMXFhM2RPYlVab1drUnJhV1pXTUhOSmJVWXhaRWRvYkdKdVVuQlpNa1l3WVZjNWRVbHFjR0pKYVU1M1kyMXNkRmxZU2pWSmJEQnpTVzFHZW1NeVZubGtSMngyWW1zeGJHUkhhSFphUTBrMlYzbEphbU5JU25CaVYwWjVaVk5LWkdaUklpd2ljMmxuYm1GMGRYSmxJam9pYm5aT1QxOXhZbEpQZGpKUmFEQmZlVjl6TVZZNGRHNUhYemxqYlhGWFpqSlVTRE41YnpOdFZGVk1XVFJxUlhWcVZVVkdNbkZ1T1haSmJVeGlNbVp5YUc1b01FZHFXa3RzT0VaRlJIY3dhM3BUZEhSTVRHY2lmUSNwcmltYXJ5In0.eb746e0a1468ce81dfa604c6de1b127b5572f4dd65426d01b197ea14d91d90a3163a6f66cf153c4ae05078503c356a5144ecb30dd1336d4a78f75b545a367f1c'
    const credentialOfferResponseToken =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpbnRlcmFjdGlvblRva2VuIjp7ImNhbGxiYWNrVVJMIjoiIiwic2VsZWN0ZWRDcmVkZW50aWFscyI6W3sidHlwZSI6Ik5hbWVDcmVkZW50aWFsUGVyc29uVjEifV19LCJleHAiOjI1MjQ2MTE2MDAwMDAsInR5cCI6ImNyZWRlbnRpYWxPZmZlclJlc3BvbnNlIiwianRpIjoiYWJhMzkxYzgzODMxZmM5NSIsImF1ZCI6ImRpZDplbGVtOkVpQjlSMHdiUUdyTGkzcEVlSGJwUTl1THFWYkpuVWtFMTJEUGhnMkhKR3diakE7ZWxlbTppbml0aWFsLXN0YXRlPWV5SndjbTkwWldOMFpXUWlPaUpsZVVwMlkwZFdlVmxZVW5CaU1qUnBUMmxLYW1OdFZtaGtSMVZwVEVOS2NtRlhVV2xQYVVscVkwaEtjR0pYUm5sbFUwbHpTVzFHYzFwNVNUWkphMVpVVFdwVk1sTjVTamtpTENKd1lYbHNiMkZrSWpvaVpYbEtRVmt5T1hWa1IxWTBaRU5KTmtsdGFEQmtTRUo2VDJrNGRtUjZUbkJhUXpWMlkyMWpkbU15Vm1wa1dFcHdaRWhyZG1ScVNXbE1RMHAzWkZkS2MyRlhUa3hhV0d0cFQyeDBOMGx0Ykd0SmFtOXBTVE5DZVdGWE1XaGpibXRwVEVOS01XTXlSbTVhVTBrMlNXNU9jRm95TlhCaWJXTnBURU5LTUdWWVFteEphbTlwVlRKV2FtTkVTVEZPYlhONFZtMVdlV0ZYV25CWk1rWXdZVmM1ZFZNeVZqVk5ha0Y0VDBOSmMwbHVRakZaYlhod1dUQjBiR1ZWYUd4bFEwazJTV3BCZWxwcVJYZFpNbFpwV21wU2FVMVVVVEpOUkVWNFRWUkpNazlFU21wTk1sa3dUa1JKZWxwVVJtaGFiVlUxV1dwU2FsbFVRbXhOZWsxNVRrUkZNbGx0V21oT2VrRXdUbGROTTAxSFNtdE5WMGt3V1dwc2FVMVRTamxNU0hOcFlWZFJhVTlwU1dwamJWWnFZak5hYkdOdWEybE1RMG94WXpKR2JscFRTVFpKYmtwc1dUSTVNbHBZU2pWSmFYZHBaRWhzZDFwVFNUWkpiRTVzV1ROQmVVNVVXbkpOVmxwc1kyMXNiV0ZYVG1oa1IyeDJZbXQwYkdWVVNYZE5WR2RwVEVOS2QyUlhTbk5oVjA1TVdsaHNTVnBZWjJsUGFVbDNUWHBWZWxsNmF6Vk5WMFV6V21wbmVscHRTbWhhUjFwdFRrUkthbHBYVlRWT1YxWnRUa1JuTUZscVFUVk9NbGt4VFZSV2JFMXRVbXRhVkZWNFRsUkJNazlYVVRGTlJGcG9XWHBGZUUxcWEzZE9iVVpvV2tScmFXWldNSE5KYlVZeFpFZG9iR0p1VW5CWk1rWXdZVmM1ZFVscWNHSkphVTUzWTIxc2RGbFlTalZKYkRCelNXMUdlbU15Vm5sa1IyeDJZbXN4YkdSSGFIWmFRMGsyVjNsSmFtTklTbkJpVjBaNVpWTktaR1pSSWl3aWMybG5ibUYwZFhKbElqb2liblpPVDE5eFlsSlBkakpSYURCZmVWOXpNVlk0ZEc1SFh6bGpiWEZYWmpKVVNETjViek50VkZWTVdUUnFSWFZxVlVWR01uRnVPWFpKYlV4aU1tWnlhRzVvTUVkcVdrdHNPRVpGUkhjd2EzcFRkSFJNVEdjaWZRIiwiaXNzIjoiZGlkOmVsZW06RWlCOVIwd2JRR3JMaTNwRWVIYnBROXVMcVZiSm5Va0UxMkRQaGcySEpHd2JqQTtlbGVtOmluaXRpYWwtc3RhdGU9ZXlKd2NtOTBaV04wWldRaU9pSmxlVXAyWTBkV2VWbFlVbkJpTWpScFQybEthbU50Vm1oa1IxVnBURU5LY21GWFVXbFBhVWxxWTBoS2NHSlhSbmxsVTBselNXMUdjMXA1U1RaSmExWlVUV3BWTWxONVNqa2lMQ0p3WVhsc2IyRmtJam9pWlhsS1FWa3lPWFZrUjFZMFpFTkpOa2x0YURCa1NFSjZUMms0ZG1SNlRuQmFRelYyWTIxamRtTXlWbXBrV0Vwd1pFaHJkbVJxU1dsTVEwcDNaRmRLYzJGWFRreGFXR3RwVDJ4ME4wbHRiR3RKYW05cFNUTkNlV0ZYTVdoamJtdHBURU5LTVdNeVJtNWFVMGsyU1c1T2NGb3lOWEJpYldOcFRFTktNR1ZZUW14SmFtOXBWVEpXYW1ORVNURk9iWE40Vm0xV2VXRlhXbkJaTWtZd1lWYzVkVk15VmpWTmFrRjRUME5KYzBsdVFqRlpiWGh3V1RCMGJHVlZhR3hsUTBrMlNXcEJlbHBxUlhkWk1sWnBXbXBTYVUxVVVUSk5SRVY0VFZSSk1rOUVTbXBOTWxrd1RrUkplbHBVUm1oYWJWVTFXV3BTYWxsVVFteE5lazE1VGtSRk1sbHRXbWhPZWtFd1RsZE5NMDFIU210TlYwa3dXV3BzYVUxVFNqbE1TSE5wWVZkUmFVOXBTV3BqYlZacVlqTmFiR051YTJsTVEwb3hZekpHYmxwVFNUWkpia3BzV1RJNU1scFlTalZKYVhkcFpFaHNkMXBUU1RaSmJFNXNXVE5CZVU1VVduSk5WbHBzWTIxc2JXRlhUbWhrUjJ4MlltdDBiR1ZVU1hkTlZHZHBURU5LZDJSWFNuTmhWMDVNV2xoc1NWcFlaMmxQYVVsM1RYcFZlbGw2YXpWTlYwVXpXbXBuZWxwdFNtaGFSMXB0VGtSS2FscFhWVFZPVjFadFRrUm5NRmxxUVRWT01sa3hUVlJXYkUxdFVtdGFWRlY0VGxSQk1rOVhVVEZOUkZwb1dYcEZlRTFxYTNkT2JVWm9Xa1JyYVdaV01ITkpiVVl4WkVkb2JHSnVVbkJaTWtZd1lWYzVkVWxxY0dKSmFVNTNZMjFzZEZsWVNqVkpiREJ6U1cxR2VtTXlWbmxrUjJ4Mlltc3hiR1JIYUhaYVEwazJWM2xKYW1OSVNuQmlWMFo1WlZOS1pHWlJJaXdpYzJsbmJtRjBkWEpsSWpvaWJuWk9UMTl4WWxKUGRqSlJhREJmZVY5ek1WWTRkRzVIWHpsamJYRlhaakpVU0RONWJ6TnRWRlZNV1RScVJYVnFWVVZHTW5GdU9YWkpiVXhpTW1aeWFHNW9NRWRxV2t0c09FWkZSSGN3YTNwVGRIUk1UR2NpZlEjcHJpbWFyeSJ9.e7fb3a5fe3dc0e17a60859470085bba4b4d04e13b1bbae3e3094e3a9eb2f27ae62c42b4c87e3eafba6ed5caeec6788a2d52254677fd837c62eb189c1496b0666'

    const tokenObject = CommonNetworkMember.fromJWT(credentialOfferResponseToken)

    const {
      payload: { interactionToken },
    } = tokenObject
    const { selectedCredentials: credentials } = interactionToken

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    const { isValid, did, nonce, selectedCredentials } = await commonNetworkMember.verifyCredentialOfferResponseToken(
      credentialOfferResponseToken,
      credentialOfferRequestToken,
    )

    expect(did).to.exist
    expect(selectedCredentials).to.deep.equal(credentials)
    expect(nonce).to.exist
    expect(isValid).to.equal(true)
    expect(selectedCredentials).to.exist
  })

  it('#verifyCredentialOfferResponseToken throws `COR-1 / 400` when bad parameters passed', async () => {
    const credentialOfferRequestToken = 123
    const credentialOfferResponseToken = 456
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.verifyCredentialOfferResponseToken(
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        credentialOfferResponseToken,
        credentialOfferRequestToken,
      )
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode } = responseError

    expect(code).to.equal('COR-1')
    expect(httpStatusCode).to.equal(400)
  })

  it('#verifyCredentialOfferResponseToken throws `ISS-12 / 400` when token is not valid (no suppliedCredentials)', async () => {
    const credentialOfferResponseToken =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.verifyCredentialOfferResponseToken(credentialOfferResponseToken)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode } = responseError

    expect(code).to.equal('ISS-12')
    expect(httpStatusCode).to.equal(400)
  })

  it('#storeEncryptedSeed throws `WAL-2 / 409` WHEN key for userId already exists', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.storeEncryptedSeed(cognitoUsername, cognitoPassword)
      await commonNetworkMember.storeEncryptedSeed(cognitoUsername, cognitoPassword)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode } = responseError

    expect(code).to.equal('WAL-2')
    expect(httpStatusCode).to.equal(409)
  })

  it('#pullEncryptedSeed', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    const pulledEncryptedSeed = await commonNetworkMember.pullEncryptedSeed(cognitoUsername, cognitoPassword)

    expect(pulledEncryptedSeed).to.exist
  })

  it('#pullEncryptedSeed throws `COR-4 / 404` when seed not found', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.pullEncryptedSeed('non_existing_user', cognitoPassword)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode } = responseError

    expect(code).to.equal('COR-4')
    expect(httpStatusCode).to.equal(404)
  })

  it('#pullEncryptedSeed throws `COR-1 / 400` when bad parameters passed', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError
    const wrongParameter1 = 123
    const wrongParameter2 = 456

    try {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      await commonNetworkMember.pullEncryptedSeed(wrongParameter1, wrongParameter2)
    } catch (error) {
      responseError = error
    }

    const {
      code,
      httpStatusCode,
      message,
      context: { errors },
    } = responseError

    const [error1, error2] = errors

    const expectedError1 = { value: wrongParameter1, message: `Parameter "${wrongParameter1}" should be a string.` }
    const expectedError2 = { value: wrongParameter2, message: `Parameter "${wrongParameter2}" should be a string.` }

    expect(code).to.equal('COR-1')
    expect(message).to.equal('Invalid operation parameters.')
    expect(httpStatusCode).to.equal(400)
    expect(error1).to.deep.equal(expectedError1)
    expect(error2).to.deep.equal(expectedError2)
  })

  it('Auth flow', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)
    const customNonce = '1231sdfd23123s'
    const audienceDid = commonNetworkMember.did
    const jwtOptions = { audienceDid, nonce: customNonce, callbackUrl }

    const requestToken = await commonNetworkMember.generateDidAuthRequest(jwtOptions)
    expect(requestToken).to.exist

    const requestTokenObject = CommonNetworkMember.fromJWT(requestToken)
    const { payload: requestPayload } = requestTokenObject
    expect(requestPayload.aud).to.be.equal(audienceDid)
    expect(requestPayload.jti).to.be.equal(customNonce)

    const responseToken = await commonNetworkMember.createDidAuthResponse(requestToken)
    expect(responseToken).to.exist
    const responseTokenObject = CommonNetworkMember.fromJWT(responseToken)

    expect(responseTokenObject.payload.jti).to.be.equal(customNonce)

    const { isValid } = await commonNetworkMember.verifyDidAuthResponse(responseToken, requestToken)
    expect(isValid).to.be.equal(true)
  })

  it('#signUp when user registers with arbitrary username', async () => {
    const cognitoUsername = generateUsername()

    const signUpNetworkMember = await CommonNetworkMember.signUp(cognitoUsername, cognitoPassword, options)
    expect(signUpNetworkMember).to.be.an.instanceof(CommonNetworkMember)
    if (typeof signUpNetworkMember === 'string') {
      expect.fail('TS type guard')
    }

    expect(signUpNetworkMember.did).to.exist
    expect(signUpNetworkMember).to.be.an.instanceof(CommonNetworkMember)

    await signUpNetworkMember.signOut(options)

    const fromLoginNetworkMember = await CommonNetworkMember.fromLoginAndPassword(
      cognitoUsername,
      cognitoPassword,
      options,
    )

    expect(fromLoginNetworkMember).to.be.an.instanceof(CommonNetworkMember)
  })

  it('#pullEncryptedSeed throws `WAL-1 / 404` WHEN key for userId does not exist', async () => {
    const cognitoUsername = userWithoutKey

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.pullEncryptedSeed(cognitoUsername, cognitoPassword)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode } = responseError

    expect(code).to.equal('WAL-1')
    expect(httpStatusCode).to.equal(404)
  })

  it('#storeEncryptedSeed throws `COR-4 / 404` WHEN userId does not exists', async () => {
    const cognitoUsername = 'non_existing@email.com'

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let responseError

    try {
      await commonNetworkMember.storeEncryptedSeed(cognitoUsername, cognitoPassword)
    } catch (error) {
      responseError = error
    }

    const { code, httpStatusCode } = responseError

    expect(code).to.equal('COR-4')
    expect(httpStatusCode).to.equal(404)
  })

  it('#changeUsername throws `COR-7 / 409` when new username exists', async () => {
    const newCognitoUsername = COGNITO_USERNAME_EXISTS

    const networkMember = await CommonNetworkMember.fromLoginAndPassword(cognitoUsername, cognitoPassword, options)

    let responseError

    try {
      await networkMember.changeUsername(newCognitoUsername, options)
    } catch (error) {
      responseError = error
    }

    const { code, message, httpStatusCode } = responseError

    expect(code).to.equal('COR-7')
    expect(message).to.equal('User with the given username already exists.')
    expect(httpStatusCode).to.equal(409)
  })

  it('#signIn with phoneNumber returns token', async () => {
    const token = await CommonNetworkMember.signIn(phoneNumber, options)

    expect(token).to.exist
  })

  it('#pullEncryptedSeed when bad parameters passed', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let validationError

    try {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      await commonNetworkMember.pullEncryptedSeed(123)
    } catch (error) {
      validationError = error
    }

    const { name, message, context, httpStatusCode } = validationError
    const { message: contextMessage1 } = context.errors[0]
    const { message: contextMessage2 } = context.errors[1]

    expect(name).to.eql('COR-1')
    expect(httpStatusCode).to.eql(400)
    expect(message).to.eql('Invalid operation parameters.')
    expect(contextMessage1).to.eql('Parameter "123" should be a string.')
    expect(contextMessage2).to.eql('Required parameter at index [1] is missing.')
  })

  it('#createCredentialShareResponseToken when bad parameters passed', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeed, options)

    let validationError

    try {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      await commonNetworkMember.createCredentialShareResponseToken()
    } catch (error) {
      validationError = error
    }

    const { name, message, context, httpStatusCode } = validationError
    const { message: contextMessage1 } = context.errors[0]

    expect(name).to.eql('COR-1')
    expect(message).to.eql('Invalid operation parameters.')
    expect(contextMessage1).to.eql('Required parameter at index [0] is missing.')
    expect(httpStatusCode).to.eql(400)
  })

  it('#getSignupCredentials', async () => {
    // NOTE: Get full options because UserManagementService will use staging variables
    //       and `options` has only accessApiKey and env
    //       This is important for testing against different environments
    const fullOptions = getAllOptionsForEnvironment()
    const userManagementService = new UserManagementService(fullOptions)

    const { idToken } = await userManagementService.logInWithPassword(cognitoUsername, cognitoPassword)

    const decoded = jwtDecode(idToken)

    if (typeof decoded === 'string') {
      throw Error
    }

    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)

    const signedCredentials = await commonNetworkMember.getSignupCredentials(idToken, options)

    expect(signedCredentials).to.exist
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    expect(signedCredentials[0].credentialSubject.data.email).to.eq(decoded.email)
  })

  it('#saveCredentials', async () => {
    const credentials = [credential]
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)

    const result = await commonNetworkMember.saveCredentials(credentials)

    expect(result[0].credentialId).to.eql(credential.id)
  })

  it('#getCredentialById', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)

    const result = await commonNetworkMember.getCredentialById(credential.id)

    const parsedCredential = JSON.parse(result)
    expect(parsedCredential.id).to.eql(credential.id)
  })

  it('#getAllCredentials', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)

    const result = await commonNetworkMember.getAllCredentials([])

    const parsedCredential = JSON.parse(result[0])
    expect(parsedCredential.id).to.eql(credential.id)
  })

  it('#getAllCredentials by types', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)

    const result = await commonNetworkMember.getAllCredentials([credential.type])

    const parsedCredential = JSON.parse(result[0])
    expect(parsedCredential.id).to.eql(credential.id)
  })

  it('#deleteCredentialById', async () => {
    const commonNetworkMember = new CommonNetworkMember(password, encryptedSeedElem, options)
    await commonNetworkMember.deleteCredentialById(credential.id)
  })
})
