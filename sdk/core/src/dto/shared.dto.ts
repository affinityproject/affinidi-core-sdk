import {
  IsBoolean,
  IsDefined,
  IsOptional,
  IsISO8601,
  IsUrl,
  IsNumber,
  IsObject,
  IsString,
  IsArray,
  IsJWT,
  Matches,
  IsIn,
  IsInt,
  Min,
} from 'class-validator'

import { FreeFormObject } from '../shared/interfaces'
import { SUPPORTED_DID_METHODS, SUPPORTED_ENVIRONMENTS } from '../_defaultConfig'

export type Env = 'dev' | 'staging' | 'prod'
export type DidMethod = 'jolo' | 'elem'
export const DID_METHOD = /^(jolo|elem)$/
export const DID = /^did:[\w\d]{2,}:[\w\d:;\-=]{10,}/
export const PASSWORD = /^.{6,}$/
export const JWT = /^[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.?[A-Za-z0-9_.+/=-]*$/
export const COGNITO_CONFIRMATION_CODE = /^\d{6}$/

export class SdkOptions {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  registryUrl?: string

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  issuerUrl?: string

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  verifierUrl?: string

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  keyStorageUrl?: string

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  bloomVaultUrl?: string

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  affinidiVaultUrl?: string

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  revocationUrl?: string

  @IsOptional()
  cognitoUserTokens?: CognitoUserTokens

  @IsOptional()
  @IsIn(SUPPORTED_DID_METHODS)
  didMethod?: DidMethod

  @IsIn(SUPPORTED_ENVIRONMENTS)
  env: Env

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  phoneIssuerBasePath?: string

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  emailIssuerBasePath?: string

  @IsBoolean()
  @IsOptional()
  skipBackupEncryptedSeed?: boolean

  @IsBoolean()
  @IsOptional()
  skipBackupCredentials?: boolean

  @IsOptional()
  apiKey?: string

  @IsOptional()
  accessApiKey?: string

  @IsBoolean()
  @IsOptional()
  isProfilerActive?: boolean

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  metricsUrl?: string

  @IsOptional()
  storageRegion?: string
}

export class MessageParameters {
  message: string

  @IsOptional()
  @IsString()
  subject?: string

  @IsOptional()
  @IsString()
  htmlMessage?: string
}

export class KeyParams {
  @IsString()
  encryptedSeed?: string

  @IsString()
  password?: string
}

export class CognitoUserTokens {
  @IsOptional()
  @IsString()
  accessToken?: string

  @IsOptional()
  @IsString()
  idToken?: string

  @IsOptional()
  @IsString()
  refreshToken?: string

  @IsOptional()
  @IsNumber()
  expiresIn?: number
}

export class SdkOptionsWithCongitoSetup extends SdkOptions {
  @IsOptional()
  @IsString()
  userPoolId?: string

  @IsOptional()
  @IsString()
  clientId?: string
}

export class CredentialParams {
  @IsDefined()
  @IsString()
  type: string

  @IsDefined()
  @IsArray()
  context: FreeFormObject[]

  @IsDefined()
  @IsObject()
  credentialSubject: FreeFormObject

  @IsOptional()
  @IsISO8601()
  expiresAt?: string
}

export class SignedCredential {
  // legacy attributes - to be deleted after support is dropped
  @IsOptional()
  @IsObject()
  claim?: FreeFormObject

  @IsOptional()
  @IsISO8601()
  issued?: string

  @IsOptional()
  @IsISO8601()
  expires?: string

  // current structure according to W3C https://www.w3.org/TR/vc-data-model
  @IsDefined()
  @IsArray()
  '@context': (FreeFormObject | string)[]

  @IsDefined()
  @IsString()
  id: string

  @IsOptional()
  @IsString()
  name?: string

  // NOTE, according to W3C it can be a string or an object
  // https://www.w3.org/TR/vc-data-model/#issuer
  // @Matches(DID) - can be any string (f.e. URL) or an object ^^
  @IsDefined()
  issuer: string | FreeFormObject

  @IsOptional()
  @IsISO8601()
  issuanceDate?: string

  @IsOptional()
  @IsISO8601()
  expirationDate?: string

  @IsDefined()
  @IsArray()
  type: string[]

  // NOTE, according to W3C it can be an object or an array of objects
  // https://www.w3.org/TR/vc-data-model/#credential-subject
  @IsOptional()
  credentialSubject?: FreeFormObject | FreeFormObject[]

  @IsDefined()
  @IsObject()
  proof: Proof

  @IsOptional()
  @IsObject()
  credentialStatus?: FreeFormObject

  @IsOptional()
  @IsArray()
  verifiableCredential?: FreeFormObject[]

  @IsOptional()
  @IsObject()
  credentialSchema?: FreeFormObject

  @IsOptional()
  @IsObject()
  refreshService?: FreeFormObject

  @IsOptional()
  @IsArray()
  termsOfUse?: FreeFormObject[]

  @IsOptional()
  @IsArray()
  evidence?: FreeFormObject[]
}

export class CredentialRequirement {
  @IsDefined()
  @IsArray()
  type: string[]
}

export class JwtOptions {
  @IsOptional()
  @Matches(DID)
  audienceDid?: string

  @IsOptional()
  @IsISO8601()
  expiresAt?: string

  @IsOptional()
  @IsString()
  nonce?: string

  // eslint-disable-next-line @typescript-eslint/naming-convention
  @IsUrl({ require_tld: false })
  @IsOptional()
  callbackUrl?: string
}

export class OfferedCredential {
  @IsDefined()
  @IsString()
  type: string

  @IsOptional()
  renderInfo?: FreeFormObject
}

// export class SignedCredentialContext {
//   id: string;
//   type: string;
//   cred: string;
//   schema: string;
//   email: string;
//   [key: string]: string;
// }

export class Proof {
  @IsDefined()
  @IsString()
  type: string
}

export class ClaimMetadata {
  @IsOptional()
  context?: (FreeFormObject | string) | (FreeFormObject | string)[]

  @IsOptional()
  @IsString()
  name?: string

  @IsOptional()
  @IsArray()
  type?: string[]

  @IsOptional()
  claimInterface?: FreeFormObject
}

export class SignCredentialOptionalInput {
  @IsOptional()
  @Matches(DID)
  requesterDid?: string

  @IsOptional()
  @IsJWT()
  credentialOfferResponseToken?: string
}

export class FetchCredentialsPaginationOptions {
  @IsOptional()
  @IsInt()
  @Min(0)
  skip?: number

  @IsOptional()
  @IsInt()
  @Min(1)
  limit?: number
}
