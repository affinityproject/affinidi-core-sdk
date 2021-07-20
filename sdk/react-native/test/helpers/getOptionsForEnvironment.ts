import {
  DEV_AFFINIDI_VAULT_URL,
  PROD_AFFINIDI_VAULT_URL,
  DEV_REGISTRY_URL,
  STAGING_AFFINIDI_VAULT_URL,
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
} from '@affinidi/wallet-core-sdk/dist/_defaultConfig'

const { TEST_SECRETS, TEST_AGAINST } = process.env
const { DEV_API_KEY_HASH, PROD_API_KEY_HASH, STAGING_API_KEY_HASH } = JSON.parse(TEST_SECRETS)

let clientId
let vaultUrl
let userPoolId
let registryUrl
let accessApiKey
let keyStorageUrl
let revocationUrl // NOTE: ISSUER_URL is used

let environment = 'staging'

if (TEST_AGAINST === 'dev' || TEST_AGAINST === 'prod') {
  environment = TEST_AGAINST
}

export const getOptionsForEnvironment = (returnAllOptionsForEnvironment = false): any => {
  const env = environment

  switch (environment) {
    case 'dev':
      clientId = DEV_COGNITO_CLIENT_ID
      vaultUrl = DEV_AFFINIDI_VAULT_URL
      userPoolId = DEV_COGNITO_USER_POOL_ID
      registryUrl = DEV_REGISTRY_URL
      accessApiKey = DEV_API_KEY_HASH
      revocationUrl = DEV_REVOCATION_URL
      keyStorageUrl = DEV_KEY_STORAGE_URL
      break

    case 'prod':
      clientId = PROD_COGNITO_CLIENT_ID
      vaultUrl = PROD_AFFINIDI_VAULT_URL
      userPoolId = PROD_COGNITO_USER_POOL_ID
      registryUrl = PROD_REGISTRY_URL
      accessApiKey = PROD_API_KEY_HASH
      revocationUrl = PROD_REVOCATION_URL
      keyStorageUrl = PROD_KEY_STORAGE_URL
      break

    default:
      vaultUrl = STAGING_AFFINIDI_VAULT_URL
      clientId = STAGING_COGNITO_CLIENT_ID
      userPoolId = STAGING_COGNITO_USER_POOL_ID
      registryUrl = STAGING_REGISTRY_URL
      accessApiKey = STAGING_API_KEY_HASH
      revocationUrl = STAGING_REVOCATION_URL
      keyStorageUrl = STAGING_KEY_STORAGE_URL
      break
  }

  if (returnAllOptionsForEnvironment) {
    return { env, revocationUrl, vaultUrl, clientId, accessApiKey, userPoolId, registryUrl, keyStorageUrl }
  }

  return { env, accessApiKey }
}
