import { test, expect } from '@playwright/test'
import { TEST_CREDENTIALS } from '../../fixtures/test-data'

test.use({ storageState: { cookies: [], origins: [] } })

test('signs in without account fields using a registered security key', async ({ page, context }) => {
  const session = await context.newCDPSession(page)
  await session.send('WebAuthn.enable')
  await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })

  await page.addInitScript(() => localStorage.setItem('npg_language', 'en'))
  await page.goto('/')
  await page.locator('#username').fill(TEST_CREDENTIALS.username)
  await page.locator('#password').fill(TEST_CREDENTIALS.password)
  await page.getByRole('button', { name: 'Sign In', exact: true }).click()

  const account = page.locator('header').getByText(TEST_CREDENTIALS.username, { exact: true })
  const openKeys = async () => {
    await account.click()
    await page.getByRole('button', { name: 'Security Keys', exact: true }).click()
  }

  const name = `Test security key ${Date.now()}`
  await openKeys()
  await page.getByRole('button', { name: 'Add security key', exact: true }).click()
  await expect(page.getByLabel('Security key name')).toBeFocused()
  await page.getByLabel('Security key name').fill(name)
  await page.getByLabel('Current Password').fill(TEST_CREDENTIALS.password)
  await page.getByRole('button', { name: 'Add security key', exact: true }).click()
  await expect(page.getByText(name, { exact: true })).toBeVisible()

  await page.goto('/')
  await page.getByRole('button', { name: 'Logout', exact: true }).click()
  await expect(page.locator('#username')).toHaveValue('')
  await expect(page.locator('#password')).toHaveValue('')

  const finishPath = '/api/v1/auth/passkey/login/finish'
  const completed = page.waitForResponse((response) => new URL(response.url()).pathname === finishPath)
  const signIn = page.getByRole('button', { name: 'Sign in with a security key', exact: true })
  await signIn.click()
  const response = await completed
  expect(response.status()).toBe(200)
  await expect(account).toBeVisible()

  const repeated = await page.request.post(finishPath, {
    headers: { Origin: new URL(page.url()).origin },
    data: response.request().postDataJSON(),
  })
  expect(repeated.status()).toBe(401)

  await openKeys()
  const keyRow = page.getByRole('listitem').filter({ hasText: name })
  await keyRow.getByRole('button', { name: 'Remove', exact: true }).click()
  await page.getByLabel('Current Password').fill(TEST_CREDENTIALS.password)
  await page.getByRole('form', { name: 'Remove', exact: true }).getByRole('button', { name: 'Remove', exact: true }).click()
  await expect(keyRow).toHaveCount(0)

  await page.goto('/')
  await page.getByRole('button', { name: 'Logout', exact: true }).click()
  const removed = page.waitForResponse((result) => new URL(result.url()).pathname === finishPath)
  await signIn.click()
  expect((await removed).status()).toBe(401)
  await expect(account).toHaveCount(0)
})
