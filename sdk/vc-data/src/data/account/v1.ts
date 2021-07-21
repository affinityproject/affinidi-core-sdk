import { VCV1, VCV1Subject } from '@affinidi/vc-common'

import { GovernmentOrgV1, PersonEV1, OrganizationEV1, getBaseV1ContextEntries, MonetaryAmountRV1 } from '../base'
import {
  CreateThing,
  MaybeArray,
  ExpandThing,
  ExtendThing,
  CreateExpandedThing,
  Type,
  createContextEntry,
  createVCContextEntry,
} from '../util'

// Helper Types

export type AccountStatementV1 = CreateThing<
  'AccountStatement',
  {
    statementDate?: string
    dueDate?: string
  }
>

export type AccountPaymentV1 = CreateThing<
  'AccountPayment',
  {
    paymentDate?: string
    amount: ExpandThing<MonetaryAmountRV1>
  }
>

type ServiceAccountStatementV1Mixin = CreateThing<
  'ServiceAccountStatement',
  {
    balanceAdjustments?: ExpandThing<MonetaryAmountRV1>
    totalBill?: ExpandThing<MonetaryAmountRV1>
    serviceAddress?: CreateExpandedThing<'PostalAddress'>
    billingAddress?: CreateExpandedThing<'PostalAddress'>
  }
>

export type ServiceAccountStatementV1 = ExtendThing<ServiceAccountStatementV1Mixin, AccountStatementV1>

export type BankAccountTransactionV1 = CreateThing<
  'BankAccountTransaction',
  {
    transactionType: 'credit' | 'debit'
    value: ExpandThing<MonetaryAmountRV1>
    memo?: string
  }
>

export type BankAccountTransactionGroupV1 = CreateThing<
  'BankAccountTransactionGroup',
  {
    identifier?: number
    startDate?: string
    endDate?: string
    cashflowCategory?: string
    cashflowSubcategory?: string
    payrollAgency?: boolean
    memo?: string
    length?: number // Length in days
    payee?: string
    payer?: string
    rank?: string
    frequency?: string // 'daily', 'weekly', 'biweekly', 'monthly', 'semiMonthly', 'annually', 'irregular', ...
    periodicity?: number
    valueStddev?: ExpandThing<MonetaryAmountRV1>
    valueTotal?: ExpandThing<MonetaryAmountRV1>
    valueMean?: ExpandThing<MonetaryAmountRV1>
    valueMedian?: ExpandThing<MonetaryAmountRV1>
    transactions?: MaybeArray<BankAccountTransactionV1>
  }
>

type OrganizationAccountV1Mixin = CreateThing<
  'OrganizationAccount',
  {
    serviceTypes?: Array<string>
    nationality?: ExpandThing<GovernmentOrgV1>
  }
>

export type OrganizationAccountV1 = ExtendThing<OrganizationAccountV1Mixin, OrganizationEV1>

export type AccountV1 = CreateThing<
  'Account',
  {
    identifier?: string | number
    organization: ExpandThing<OrganizationAccountV1>
    startDate?: string
    endDate?: string
    accountType?: string
    accountTypeConfidence?: number
    accountStatements?: Array<AccountStatementV1>
    accountPayments?: Array<AccountPaymentV1>
    hasValue?: ExpandThing<MonetaryAmountRV1>
    bankAccountCategory?: string
    hasIncome?: MaybeArray<BankAccountTransactionGroupV1>
    hasExpense?: MaybeArray<BankAccountTransactionGroupV1>
    hasTransactions?: MaybeArray<BankAccountTransactionV1>
  }
>

const getHelperContextEntries = () => {
  const accountStatementEntry = createContextEntry<AccountStatementV1>({
    type: 'AccountStatement',
    typeIdBase: 'affSchema',
    fields: {
      statementDate: 'affSchema',
      dueDate: 'affSchema',
    },
  })

  const accountPaymentEntry = createContextEntry<AccountPaymentV1>({
    type: 'AccountPayment',
    typeIdBase: 'affSchema',
    fields: {
      paymentDate: 'affSchema',
      amount: 'affSchema',
    },
  })

  const serviceAccountStatementEntry = createContextEntry<ServiceAccountStatementV1Mixin, AccountStatementV1>({
    type: 'ServiceAccountStatement',
    typeIdBase: 'affSchema',
    fields: {
      balanceAdjustments: 'affSchema',
      totalBill: 'affSchema',
      serviceAddress: 'affSchema',
      billingAddress: 'affSchema',
    },
  })

  const bankAccountTransactionV1Entry = createContextEntry<BankAccountTransactionV1>({
    type: 'BankAccountTransaction',
    typeIdBase: 'affSchema',
    fields: {
      transactionType: 'affSchema',
      value: 'affSchema',
      memo: 'affSchema',
    },
  })

  const bankAccountTransactionGroupV1Entry = createContextEntry<BankAccountTransactionGroupV1>({
    type: 'BankAccountTransactionGroup',
    typeIdBase: 'affSchema',
    fields: {
      identifier: 'affSchema',
      startDate: 'affSchema',
      endDate: 'affSchema',
      cashflowCategory: 'affSchema',
      cashflowSubcategory: 'affSchema',
      payrollAgency: 'affSchema',
      memo: 'affSchema',
      length: 'affSchema',
      payee: 'affSchema',
      payer: 'affSchema',
      rank: 'affSchema',
      frequency: 'affSchema',
      periodicity: 'affSchema',
      valueStddev: 'affSchema',
      valueTotal: 'affSchema',
      valueMean: 'affSchema',
      valueMedian: 'affSchema',
      transactions: 'affSchema',
    },
  })

  const organizationAccountEntry = createContextEntry<OrganizationAccountV1Mixin, OrganizationEV1>({
    type: 'OrganizationAccount',
    typeIdBase: 'affSchema',
    fields: {
      serviceTypes: 'affSchema',
      nationality: 'affSchema',
    },
  })

  const accountEntry = createContextEntry<AccountV1>({
    type: 'Account',
    typeIdBase: 'affSchema',
    fields: {
      identifier: 'affSchema',
      organization: 'affSchema',
      startDate: 'affSchema',
      endDate: 'affSchema',
      accountType: 'affSchema',
      accountTypeConfidence: 'affSchema',
      accountStatements: 'affSchema',
      accountPayments: 'affSchema',
      hasValue: 'affSchema',
      bankAccountCategory: 'affSchema',
      hasIncome: 'affSchema',
      hasExpense: 'affSchema',
      hasTransactions: 'affSchema',
    },
  })

  return [
    accountStatementEntry,
    accountPaymentEntry,
    serviceAccountStatementEntry,
    bankAccountTransactionV1Entry,
    bankAccountTransactionGroupV1Entry,
    organizationAccountEntry,
    accountEntry
  ]
}

// Person Related

type AccountPersonV1Mixin = CreateThing<
  'AccountPerson',
  {
    hasAccount: MaybeArray<AccountV1>
  }
>

export type AccountPersonV1 = ExtendThing<AccountPersonV1Mixin, PersonEV1>

export type VCSAccountPersonV1 = VCV1Subject<ExpandThing<AccountPersonV1>>

export type VCAccountPersonV1 = VCV1<VCSAccountPersonV1, Type<'AccountCredentialPersonV1'>>

export const getVCAccountPersonV1Context = () => {
  const accountPersonEntry = createContextEntry<AccountPersonV1Mixin, PersonEV1>({
    type: 'AccountPerson',
    typeIdBase: 'affSchema',
    fields: {
      hasAccount: 'affSchema',
    },
    vocab: 'schema',
  })

  return createVCContextEntry<VCAccountPersonV1>({
    type: 'AccountCredentialPersonV1',
    typeIdBase: 'affSchema',
    entries: [accountPersonEntry, ...getHelperContextEntries(), ...getBaseV1ContextEntries()],
    vocab: 'schema',
  })
}

// Organization Related

type AccountOrganizationV1Mixin = CreateThing<
  'AccountOrganization',
  {
    hasAccount: MaybeArray<AccountV1>
  }
>

export type AccountOrganizationV1 = ExtendThing<AccountOrganizationV1Mixin, OrganizationEV1>

export type VCSAccountOrganizationV1 = VCV1Subject<ExpandThing<AccountOrganizationV1>>

export type VCAccountOrganizationV1 = VCV1<VCSAccountOrganizationV1, Type<'AccountCredentialOrganizationV1'>>

export const getVCAccountOrganizationV1Context = () => {
  const accountOrganizationEntry = createContextEntry<AccountOrganizationV1Mixin, OrganizationEV1>({
    type: 'AccountOrganization',
    typeIdBase: 'affSchema',
    fields: {
      hasAccount: 'affSchema',
    },
    vocab: 'schema',
  })

  return createVCContextEntry<VCAccountOrganizationV1>({
    type: 'AccountCredentialOrganizationV1',
    typeIdBase: 'affSchema',
    entries: [accountOrganizationEntry, ...getHelperContextEntries(), ...getBaseV1ContextEntries()],
    vocab: 'schema',
  })
}
