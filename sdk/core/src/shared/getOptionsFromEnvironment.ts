import { KeysService } from '@affinidi/common'
import { Env, SdkOptions } from '../dto/shared.dto'

import {
  DEV_REVOCATION_URL,
  PROD_REVOCATION_URL,
  STAGING_REVOCATION_URL,
  DEV_COGNITO_CLIENT_ID,
  DEV_COGNITO_USER_POOL_ID,
  DEV_REGISTRY_URL,
  DEV_ISSUER_URL,
  DEV_VERIFIER_URL,
  DEV_KEY_STORAGE_URL,
  DEV_BLOOM_VAULT_URL,
  DEV_AFFINIDI_VAULT_URL,
  DEV_PHONE_ISSUER_BASE_PATH,
  DEV_EMAIL_ISSUER_BASE_PATH,
  STAGING_COGNITO_CLIENT_ID,
  STAGING_COGNITO_USER_POOL_ID,
  STAGING_REGISTRY_URL,
  STAGING_ISSUER_URL,
  STAGING_VERIFIER_URL,
  STAGING_KEY_STORAGE_URL,
  STAGING_BLOOM_VAULT_URL,
  STAGING_AFFINIDI_VAULT_URL,
  STAGING_PHONE_ISSUER_BASE_PATH,
  STAGING_EMAIL_ISSUER_BASE_PATH,
  PROD_COGNITO_CLIENT_ID,
  PROD_COGNITO_USER_POOL_ID,
  PROD_REGISTRY_URL,
  PROD_ISSUER_URL,
  PROD_VERIFIER_URL,
  PROD_KEY_STORAGE_URL,
  PROD_BLOOM_VAULT_URL,
  PROD_AFFINIDI_VAULT_URL,
  PROD_PHONE_ISSUER_BASE_PATH,
  PROD_EMAIL_ISSUER_BASE_PATH,
  DEV_METRICS_URL,
  STAGING_METRICS_URL,
  PROD_METRICS_URL,
} from '../_defaultConfig'

type AccessApiKeyOptions = {
  accessApiKey?: string
  apiKey?: string
}

export const getAccessApiKeyFromOptions = ({ accessApiKey, apiKey }: AccessApiKeyOptions) => {
  if (!accessApiKey && !apiKey) {
    throw new Error('Neither accessApiKey nor apiKey is contained in options')
  }

  if (apiKey) {
    const apiKeyBuffer = KeysService.sha256(Buffer.from(apiKey))
    return apiKeyBuffer.toString('hex')
  }

  return accessApiKey
}

type EnvironmentOptions = {
  env: Env
  issuerUrl?: string
  registryUrl?: string
  verifierUrl?: string
  bloomVaultUrl?: string
  affinidiVaultUrl?: string
  keyStorageUrl?: string
  phoneIssuerBasePath?: string
  emailIssuerBasePath?: string
  revocationUrl?: string
}

function getBasicOptionsFromEnvironment(options: EnvironmentOptions) {
  const env = options.env

  switch (env) {
    /* istanbul ignore next */
    case 'dev':
      return {
        env: env as Env,
        issuerUrl: options.issuerUrl || DEV_ISSUER_URL,
        registryUrl: options.registryUrl || DEV_REGISTRY_URL,
        verifierUrl: options.verifierUrl || DEV_VERIFIER_URL,
        bloomVaultUrl: options.bloomVaultUrl || DEV_BLOOM_VAULT_URL,
        affinidiVaultUrl: options.affinidiVaultUrl || DEV_AFFINIDI_VAULT_URL,
        keyStorageUrl: options.keyStorageUrl || DEV_KEY_STORAGE_URL,
        clientId: DEV_COGNITO_CLIENT_ID,
        userPoolId: DEV_COGNITO_USER_POOL_ID,
        phoneIssuerBasePath: options.phoneIssuerBasePath || DEV_PHONE_ISSUER_BASE_PATH,
        emailIssuerBasePath: options.emailIssuerBasePath || DEV_EMAIL_ISSUER_BASE_PATH,
        metricsUrl: DEV_METRICS_URL,
        revocationUrl: options.revocationUrl || DEV_REVOCATION_URL,
      }

    /* istanbul ignore next */
    case 'prod':
      return {
        env: env as Env,
        issuerUrl: options.issuerUrl || PROD_ISSUER_URL,
        registryUrl: options.registryUrl || PROD_REGISTRY_URL,
        verifierUrl: options.verifierUrl || PROD_VERIFIER_URL,
        bloomVaultUrl: options.bloomVaultUrl || PROD_BLOOM_VAULT_URL,
        affinidiVaultUrl: options.affinidiVaultUrl || PROD_AFFINIDI_VAULT_URL,
        keyStorageUrl: options.keyStorageUrl || PROD_KEY_STORAGE_URL,
        clientId: PROD_COGNITO_CLIENT_ID,
        userPoolId: PROD_COGNITO_USER_POOL_ID,
        phoneIssuerBasePath: options.phoneIssuerBasePath || PROD_PHONE_ISSUER_BASE_PATH,
        emailIssuerBasePath: options.emailIssuerBasePath || PROD_EMAIL_ISSUER_BASE_PATH,
        metricsUrl: PROD_METRICS_URL,
        revocationUrl: options.revocationUrl || PROD_REVOCATION_URL,
      }

    case 'staging':
      return {
        env: env as Env,
        issuerUrl: options.issuerUrl || STAGING_ISSUER_URL,
        registryUrl: options.registryUrl || STAGING_REGISTRY_URL,
        verifierUrl: options.verifierUrl || STAGING_VERIFIER_URL,
        bloomVaultUrl: options.bloomVaultUrl || STAGING_BLOOM_VAULT_URL,
        affinidiVaultUrl: options.affinidiVaultUrl || STAGING_AFFINIDI_VAULT_URL,
        keyStorageUrl: options.keyStorageUrl || STAGING_KEY_STORAGE_URL,
        clientId: STAGING_COGNITO_CLIENT_ID,
        userPoolId: STAGING_COGNITO_USER_POOL_ID,
        phoneIssuerBasePath: options.phoneIssuerBasePath || STAGING_PHONE_ISSUER_BASE_PATH,
        emailIssuerBasePath: options.emailIssuerBasePath || STAGING_EMAIL_ISSUER_BASE_PATH,
        metricsUrl: STAGING_METRICS_URL,
        revocationUrl: options.revocationUrl || STAGING_REVOCATION_URL,
      }
  }
}

const splitOptions = <TOptions extends SdkOptions>(options: TOptions) => {
  const {
    accessApiKey,
    apiKey,
    env,
    issuerUrl,
    registryUrl,
    verifierUrl,
    bloomVaultUrl,
    affinidiVaultUrl,
    keyStorageUrl,
    phoneIssuerBasePath,
    emailIssuerBasePath,
    revocationUrl,
    storageRegion,
    cognitoUserTokens,
    ...otherOptions
  } = options

  return {
    accessApiKeyOptions: {
      accessApiKey,
      apiKey,
    },
    environmentOptions: {
      env,
      issuerUrl,
      registryUrl,
      verifierUrl,
      bloomVaultUrl,
      affinidiVaultUrl,
      keyStorageUrl,
      phoneIssuerBasePath,
      emailIssuerBasePath,
      revocationUrl,
    },
    storageRegion,
    cognitoUserTokens,
    otherOptions,
  }
}

export const getOptionsFromEnvironment = <TOptions extends SdkOptions>(options: TOptions) => {
  const { accessApiKeyOptions, environmentOptions, storageRegion, cognitoUserTokens, otherOptions } = splitOptions(
    options,
  )

  return {
    basicOptions: getBasicOptionsFromEnvironment(environmentOptions),
    accessApiKey: getAccessApiKeyFromOptions(accessApiKeyOptions),
    storageRegion,
    cognitoUserTokens,
    otherOptions,
  }
}
