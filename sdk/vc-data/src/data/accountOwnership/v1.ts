import { CreateThing, createContextEntry, AddKeyPairs } from '../util'

export type AccountOwnershipV1 = CreateThing<
  'AccountOwnership',
  {
    accountName: string,
    accountType: string,
    metaData: AddKeyPairs<any>
  }
  >

export const getHelperContextEntries = () => {
  const accountOwnershipEntry = createContextEntry<AccountOwnershipV1>({
    type: 'AccountOwnership',
    typeIdBase: 'affSchema',
    fields: {
      accountName: 'affSchema',
      accountType: 'affSchema',
      metaData: 'affSchema'
    },
    vocab: 'schema',
  })

  return [
    accountOwnershipEntry
  ]
}
