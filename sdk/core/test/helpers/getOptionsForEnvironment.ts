import { Env } from '../../src/dto/shared.dto'
import {
  DEV_AFFINIDI_VAULT_URL,
  PROD_AFFINIDI_VAULT_URL,
  DEV_BLOOM_VAULT_URL,
  PROD_BLOOM_VAULT_URL,
  DEV_REGISTRY_URL,
  STAGING_AFFINIDI_VAULT_URL,
  STAGING_BLOOM_VAULT_URL,
  PROD_REGISTRY_URL,
  DEV_REVOCATION_URL,
  PROD_REVOCATION_URL,
  DEV_KEY_STORAGE_URL,
  PROD_KEY_STORAGE_URL,
  STAGING_REGISTRY_URL,
  DEV_COGNITO_CLIENT_ID,
  PROD_COGNITO_CLIENT_ID,
  STAGING_REVOCATION_URL,
  STAGING_KEY_STORAGE_URL,
  DEV_COGNITO_USER_POOL_ID,
  PROD_COGNITO_USER_POOL_ID,
  STAGING_COGNITO_CLIENT_ID,
  STAGING_COGNITO_USER_POOL_ID,
} from '../../src/_defaultConfig'

import { TEST_AGAINST, testSecrets } from './testSecrets'
const { DEV_API_KEY_HASH, PROD_API_KEY_HASH, STAGING_API_KEY_HASH } = testSecrets

let environment: Env = 'staging'

if (TEST_AGAINST === 'dev' || TEST_AGAINST === 'prod') {
  environment = TEST_AGAINST
}

export const getAllOptionsForEnvironment = () => {
  const env = environment

  switch (env) {
    case 'dev':
      return {
        env,
        clientId: DEV_COGNITO_CLIENT_ID,
        bloomVaultUrl: DEV_BLOOM_VAULT_URL,
        affinidiVaultUrl: DEV_AFFINIDI_VAULT_URL,
        userPoolId: DEV_COGNITO_USER_POOL_ID,
        registryUrl: DEV_REGISTRY_URL,
        accessApiKey: DEV_API_KEY_HASH,
        revocationUrl: DEV_REVOCATION_URL,
        keyStorageUrl: DEV_KEY_STORAGE_URL,
      }

    case 'prod':
      return {
        env,
        clientId: PROD_COGNITO_CLIENT_ID,
        bloomVaultUrl: PROD_BLOOM_VAULT_URL,
        affinidiVaultUrl: PROD_AFFINIDI_VAULT_URL,
        userPoolId: PROD_COGNITO_USER_POOL_ID,
        registryUrl: PROD_REGISTRY_URL,
        accessApiKey: PROD_API_KEY_HASH,
        revocationUrl: PROD_REVOCATION_URL,
        keyStorageUrl: PROD_KEY_STORAGE_URL,
      }

    case 'staging':
      return {
        env,
        bloomVaultUrl: STAGING_BLOOM_VAULT_URL,
        affinidiVaultUrl: STAGING_AFFINIDI_VAULT_URL,
        clientId: STAGING_COGNITO_CLIENT_ID,
        userPoolId: STAGING_COGNITO_USER_POOL_ID,
        registryUrl: STAGING_REGISTRY_URL,
        accessApiKey: STAGING_API_KEY_HASH,
        revocationUrl: STAGING_REVOCATION_URL,
        keyStorageUrl: STAGING_KEY_STORAGE_URL,
      }
  }
}

export const getBasicOptionsForEnvironment = () => {
  const { accessApiKey, env } = getAllOptionsForEnvironment()
  return { accessApiKey, env }
}
