import { SdkError } from '@affinidi/common'

export default class SdkErrorFromCode extends SdkError {
  constructor(code: string, context: unknown = {}, originalError: unknown = {}) {
    const error = SdkErrorFromCode.errors[code]

    if (!error) {
      throw new Error(`Invalid operation error code: ${code}`)
    }

    super({ ...error, code }, context, originalError)
  }

  static get errors(): any {
    return {
      'COR-0': {
        type: 'ApplicationError',
        message: 'There was an unhandled operation error.',
        httpStatusCode: 500,
      },
      'COR-1': {
        type: 'InvalidParametersError',
        message: 'Invalid operation parameters.',
        httpStatusCode: 400,
      },
      'COR-2': {
        type: 'InvalidParametersError',
        message: 'Confirmation code expired.',
        httpStatusCode: 400,
      },
      'COR-3': {
        type: 'InvalidParametersError',
        message: 'Username should be valid email or phone number.',
        httpStatusCode: 400,
      },
      'COR-4': {
        type: 'OperationError',
        message: 'User not found.',
        httpStatusCode: 404,
      },
      'COR-5': {
        type: 'InvalidParametersError',
        message: 'Confirmation code is invalid.',
        httpStatusCode: 400,
      },
      'COR-6': {
        type: 'InvalidParametersError',
        message: 'Password requirements are not met (min length 8, number, uppercase, lowercase).',
        httpStatusCode: 400,
      },
      'COR-7': {
        type: 'OperationError',
        message: 'User with the given username already exists.',
        httpStatusCode: 409,
      },
      'COR-8': {
        type: 'OperationError',
        message: 'User already confirmed.',
        httpStatusCode: 409,
      },
      'COR-9': {
        type: 'UnprocessableEntityError',
        message: 'User must be logged in.',
        httpStatusCode: 422,
      },
      'COR-10': {
        type: 'UnprocessableEntityError',
        message: 'Not supported did method.',
        httpStatusCode: 422,
      },
      'COR-11': {
        type: 'InvalidParametersError',
        message: 'Username cannot be email or phone number.',
        httpStatusCode: 400,
      },
      'COR-12': {
        type: 'InvalidParametersError',
        message: 'Password must be provided.',
        httpStatusCode: 400,
      },
      'COR-13': {
        type: 'InvalidParametersError',
        message: 'You can enter OTP not more than 3 times. Please sign in again.',
        httpStatusCode: 400,
      },
      'COR-14': {
        type: 'OperationError',
        message: 'User does not have any credentials.',
        httpStatusCode: 404,
      },
      'COR-15': {
        type: 'InvalidParametersError',
        message: 'Function to pull request token does not return valid request token.',
        httpStatusCode: 404,
      },
      'COR-16': {
        type: 'OperationError',
        message: 'User was created but not confirmed. Please sign up again to complete registration.',
        httpStatusCode: 400,
      },
      'COR-17': {
        type: 'InvalidParametersError',
        message: 'Confirmation code expired. Please sign in again.',
        httpStatusCode: 400,
      },
      'COR-18': {
        type: 'OperationError',
        message:
          'User registration could not be completed - private key was not saved after 3 attempts. ' +
          'Username must be reset before it can be used for registration again.',
        httpStatusCode: 400,
      },
      'COR-19': {
        type: 'OperationError',
        message: 'Token expired',
        httpStatusCode: 400,
      },
      'COR-20': {
        type: 'InvalidParametersError',
        message: 'Update Did document operation supports only for jolo method.',
        httpStatusCode: 400,
      },
      'COR-21': {
        type: 'InvalidParametersError',
        message: 'Did document has another did.',
        httpStatusCode: 400,
      },
      'COR-22': {
        type: 'InvalidParametersError',
        message:
          'Offered credential types do not match any supplied credentials for signing. Check for type name mismatch.',
        httpStatusCode: 400,
      },
      'COR-23': {
        type: 'InvalidParametersError',
        message: 'Credential with id {{id}} not found.',
        httpStatusCode: 404,
      },
      'COR-24': {
        type: 'InvalidParametersError',
        message: 'Invalid encryptedSeed or password',
        httpStatusCode: 400,
      },
      'COR-25': {
        type: 'InvalidParametersError',
        message: 'did method: {{didMethod}} not supported. Supported methods: {{supportedDidMethods}}',
        httpStatusCode: 409,
      },
      'COR-26': {
        type: 'OperationError',
        message: 'Delete credential {{credentialId}} failed',
        httpStatusCode: 400,
      },
    }
  }
}
