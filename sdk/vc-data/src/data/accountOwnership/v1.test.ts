import { AccountOwnershipV1, getHelperContextEntries } from './v1'
import { expandVC } from '../../testUtil.test'

describe.skip('AccountOwnershipV1', () => {
  it('expands correctly', async () => {
    expect.assertions(1)

    const expanded = await expandVC<AccountOwnershipV1>({
      type: 'AccountOwnership',
      data: {
        // add some data
      },
      context: getHelperContextEntries(),
    })

    expect(expanded).toMatchInlineSnapshot(``)
  })
})
