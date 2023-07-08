import assert from 'assert'
import { describe, it } from 'mocha'
import { acmeServerNames, isValidHostname } from '../src/utils'

describe('utils', () => {
  describe('isValidHostname', () => {
    it('returns true for valid names', () => {
      assert(isValidHostname('nginx.com'))
      assert(isValidHostname('5guys.nginx.com'))
      assert(isValidHostname('5guys.nginx.com.'))
      assert(isValidHostname('5-guys.'))
      assert(isValidHostname('5'))
      assert(isValidHostname('a-z.123'))
      assert(isValidHostname('a.'.repeat(100)))
      assert(isValidHostname('a'.repeat(61) + '.com'))
    })
    it('returns false for invalid names', () => {
      assert(!isValidHostname('.com'))
      assert(!isValidHostname('.foobarbaz'))
      assert(!isValidHostname('*.nginx.com'))
      assert(!isValidHostname('-5guys.'))
      assert(!isValidHostname('5guys-'))
      assert(!isValidHostname('domäin.'))
      assert(!isValidHostname('  '))
      assert(!isValidHostname(''))
      assert(!isValidHostname('a'.repeat(65) + '.com'))
      assert(!isValidHostname('*'))
      assert(
        !isValidHostname(
          // too long - 256 chars
          '1234567890abcdef'.repeat(16)
        )
      )
    })
  })
  describe('acmeServerNames', () => {
    it('returns an array given valid input', () => {
      const r = {
        variables: {
          njs_acme_server_names: null,
        },
      } as unknown as NginxHTTPRequest
      const testCases = {
        'nginx.com': 1,
        'foo.bar.baz': 1,
        'foo.bar.baz foo.baz': 2,
        'foo. bar. baz.': 3,
        'foo.,bar.': 2,
        'foo.\tbar.': 2,
        'foo.        bar.': 2,
      }

      for (const [names, expected] of Object.entries(testCases)) {
        r.variables.njs_acme_server_names = names
        const result = acmeServerNames(r)
        assert(result.length === expected)
      }
    })
    it('throws given invalid input', () => {
      const r = {
        variables: {
          njs_acme_server_names: null,
        },
      } as unknown as NginxHTTPRequest
      for (const name of [
        'nginx-.com',
        '*.bar.baz',
        'foo.bar.baz *.baz',
        '-foo. bar. baz.',
      ]) {
        r.variables.njs_acme_server_names = name
        assert.throws(() => acmeServerNames(r))
      }
    })
  })
})
