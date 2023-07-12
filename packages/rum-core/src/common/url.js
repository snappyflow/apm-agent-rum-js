/**
 * MIT License
 *
 * Copyright (c) 2017-present, Elasticsearch BV
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

/**
 * Bare miniaml URL parser that is not compatible with URL Api
 * in the browser
 *
 * Does not support
 * - URLSearchParams
 * - Unicode chars, Punycode
 *
 * {
 *    hash: '',
 *    host: '',
 *    origin: '',
 *    path: ''
 *    protocol: '',
 *    query: '',
 * }
 *
 * Based on code from url-parser!
 * https://github.com/unshiftio/url-parse/blob/master/index.js
 *
 */

import { isBrowser } from './utils'
import Typo from 'typo-js'

/**
 * Add default ports for other protocols(ws, wss) after
 * RUM agent starts instrumenting those
 */
function isDefaultPort(port, protocol) {
  switch (protocol) {
    case 'http:':
      return port === '80'
    case 'https:':
      return port === '443'
  }
  return true
}

/**
 * Order of the RULES are very important
 *
 * RULE[0] -> for checking the index of the character on the URL
 * RULE[1] -> key to store the associated value present after the RULE[0]
 * RULE[2] -> Extract from the front till the last index
 * RULE[3] -> Left over values of the URL
 */
const RULES = [
  ['#', 'hash'],
  ['?', 'query'],
  ['/', 'path'],
  ['@', 'auth', 1],
  [NaN, 'host', undefined, 1]
]
const PROTOCOL_REGEX = /^([a-z][a-z0-9.+-]*:)?(\/\/)?([\S\s]*)/i

export class Url {
  constructor(url) {
    let { protocol, address, slashes } = this.extractProtocol(url || '')
    const relative = !protocol && !slashes
    const location = this.getLocation()
    const instructions = RULES.slice()
    // Sanitize what is left of the address
    address = address.replace('\\', '/')

    /**
     * When the authority component is absent the URL starts with a path component.
     * By setting it as NaN, we set the remaining parsed address to path
     */
    if (!slashes) {
      instructions[2] = [NaN, 'path']
    }

    let index
    for (let i = 0; i < instructions.length; i++) {
      const instruction = instructions[i]
      const parse = instruction[0]
      const key = instruction[1]

      if (typeof parse === 'string') {
        index = address.indexOf(parse)
        if (~index) {
          const instLength = instruction[2]
          if (instLength) {
            /**
             * we need to figure out the explicit index where the auth portion
             * in the host ends before parsing the rest of the URL as host.
             *
             * ex: http://a@b@c.com/d
             * auth -> a@b
             * host -> c.com
             */
            let newIndex = address.lastIndexOf(parse)
            index = Math.max(index, newIndex)
            this[key] = address.slice(0, index)
            address = address.slice(index + instLength)
          } else {
            this[key] = address.slice(index)
            address = address.slice(0, index)
          }
        }
      } else {
        /** NaN condition */
        this[key] = address
        address = ''
      }
      /**
       * Default values for all keys from location if url is relative
       */
      this[key] =
        this[key] || (relative && instruction[3] ? location[key] || '' : '')
      /**
       * host should be lowercased so they can be used to
       * create a proper `origin`.
       */
      if (instruction[3]) this[key] = this[key].toLowerCase()
    }

    /**
     * if the URL is relative, prepend the path with `/`
     * to construct the href correctly
     */
    if (relative && this.path.charAt(0) !== '/') {
      this.path = '/' + this.path
    }

    this.relative = relative

    this.protocol = protocol || location.protocol

    /**
     * Construct port and hostname from host
     *
     * Port numbers are not added for default ports of a given protocol
     * and hostname would match host when port is not present
     */
    this.hostname = this.host
    this.port = ''
    if (/:\d+$/.test(this.host)) {
      const value = this.host.split(':')
      const port = value.pop()
      const hostname = value.join(':')
      if (isDefaultPort(port, this.protocol)) {
        this.host = hostname
      } else {
        this.port = port
      }
      this.hostname = hostname
    }

    this.origin =
      this.protocol && this.host && this.protocol !== 'file:'
        ? this.protocol + '//' + this.host
        : 'null'

    this.href = this.toString()
  }

  toString() {
    let result = this.protocol
    result += '//'
    if (this.auth) {
      const REDACTED = '[REDACTED]'
      const userpass = this.auth.split(':')
      const username = userpass[0] ? REDACTED : ''
      const password = userpass[1] ? ':' + REDACTED : ''
      result += username + password + '@'
    }
    result += this.host
    result += this.path
    result += this.query
    result += this.hash
    return result
  }

  getLocation() {
    var globalVar = {}
    if (isBrowser) {
      globalVar = window
    }

    return globalVar.location
  }

  extractProtocol(url) {
    const match = PROTOCOL_REGEX.exec(url)
    return {
      protocol: match[1] ? match[1].toLowerCase() : '',
      slashes: !!match[2],
      address: match[3]
    }
  }
}

/**
 * Converts URL path tree in to slug based on tree depth
 */
export function slugifyUrl(urlStr, depth = 2) {
  const parsedUrl = new Url(urlStr)
  const { query, path } = parsedUrl
  const pathParts = path.substring(1).split('/')

  const redactString = ':id'
  const wildcard = '*'
  const specialCharsRegex = /\W|_/g
  const digitsRegex = /[0-9]/g
  const lowerCaseRegex = /[a-z]/g
  const upperCaseRegex = /[A-Z]/g

  const redactedParts = []
  let redactedBefore = false

  for (let index = 0; index < pathParts.length; index++) {
    const part = pathParts[index]

    if (redactedBefore || index > depth - 1) {
      if (part) {
        redactedParts.push(wildcard)
      }
      break
    }

    const numberOfSpecialChars = (part.match(specialCharsRegex) || []).length
    if (numberOfSpecialChars >= 2) {
      redactedParts.push(redactString)
      redactedBefore = true
      continue
    }

    const numberOfDigits = (part.match(digitsRegex) || []).length
    if (
      numberOfDigits > 3 ||
      (part.length > 3 && numberOfDigits / part.length >= 0.3)
    ) {
      redactedParts.push(redactString)
      redactedBefore = true
      continue
    }

    const numberofUpperCase = (part.match(upperCaseRegex) || []).length
    const numberofLowerCase = (part.match(lowerCaseRegex) || []).length
    const lowerCaseRate = numberofLowerCase / part.length
    const upperCaseRate = numberofUpperCase / part.length
    if (
      part.length > 5 &&
      ((upperCaseRate > 0.3 && upperCaseRate < 0.6) ||
        (lowerCaseRate > 0.3 && lowerCaseRate < 0.6))
    ) {
      redactedParts.push(redactString)
      redactedBefore = true
      continue
    }

    part && redactedParts.push(part)
  }

  const redacted =
    '/' +
    (redactedParts.length >= 2
      ? redactedParts.join('/')
      : redactedParts.join('')) +
    (query ? '?{query}' : '')

  return redacted
}

let dict = null

const LETTER_THRESHOLD_MIN = 0.3
const LETTER_THRESHOLD_MAX = 0.6

const UPPER_CASE_REGEX = /[A-Z]/g
const LOWER_CASE_REGEX = /[a-z]/g
const NUMERIC_REGEX = /[0-9]/g
const SPECIAL_CHAR_REGEX = /[\W_]/g
const FILE_ENDING_REGEX = /\.\w+#?$/

/***
 * isToken(part: string): boolean
 * @abstract Determines if the given string is a token or not.
 *
 * @description
 * URL path params consist of 2 types of parts - tokens and words.
 *	A part is said to be a token if it is randomly generated for a particular UUID
 *	If the part is static, then it is considered to be a word.
 *
 *	@argument part: string
 *	The URL part that has to be classified.
 *
 *	@returns
 *	true if part is a token
 *	false if part is a word
 *
 *	@example
 *	isToken("my-long-winding-string")	//	false
 *	isToken("JZHQyidcaI")				//	true
 *	isToken("vmprojects")				//	false
 */
function isToken(part) {
  //if (typeof(part) !== "string") throw (`${part} should be a string.`);

  //	Test 1 - Spellcheck test
  let misspellings = part
    .split(/[_\-]/g)
    .filter(subPart => !dict.check(subPart))

  //	If every word is perfectly spelled, probably not a token
  if (misspellings.length === 0) return false

  //	Test 2 - If a file, like "*.html" or something is encountered, probably not a token
  if (FILE_ENDING_REGEX.test(part)) return false

  //  Test 3 - Check no. of digits.
  if (NUMERIC_REGEX.test(part)) return true

  //  Test 4 - Check no. of special symbols.
  if (SPECIAL_CHAR_REGEX.test(part)) return true

  //  Test 5 - Check lowercase and uppercase ratios.
  const totalChars = part.length
  const lowerChars = (part.match(LOWER_CASE_REGEX) || []).length
  const upperChars = (part.match(UPPER_CASE_REGEX) || []).length

  const lowerRatio = lowerChars / totalChars
  const upperRatio = upperChars / totalChars

  if (lowerRatio < LETTER_THRESHOLD_MAX && lowerRatio > LETTER_THRESHOLD_MIN)
    return true
  if (upperRatio < LETTER_THRESHOLD_MAX && upperRatio > LETTER_THRESHOLD_MIN)
    return true

  //  Fulfilled the last of the conditions; it's probably not a token
  return false
}

/**
 *   sfSlugify(urlStr: string): string
 *   @abstract Special URL conversion function to work for SPAs like SnappyFlow.
 *
 *   @description
 *   This function replaces the variable parts of a given URL (called tokens) with fixed values instead.
 *   This way, we can group by transaction.name in the RUM, greatly reducing the number of transactions shown
 *   for the same view.
 *
 *   @argument urlStr: string
 *   The URL string that needs to be normalized.
 *
 *   @returns The normalized string.
 *
 *   @example
 *   sfSlugify("https://apmmanager.snappyflow.io/#/applications/JZHQyidcaI/inventory?tab=Description&instanceName=Apmmgr-prvtlink-Netlb") // /applications/:id/inventory?{query}
 */
export function sfSlugify(urlStr) {
  //  Ensure that the spellchecker is loaded with a dict
  if (!dict) {
    dict = new Typo('en-US', false, false)
  }

  //  Get the different parts of the URL
  const parsedUrl = new Url(urlStr)
  let { query, path, hash } = parsedUrl

  //  In SPAs, the true path often comes after '#'
  //  This is so that servers like apache, nginx do not interpret it as a different file that needs to be served
  //  Get the actual query for this use case
  if (hash.includes('?')) {
    query = hash.match(/\?.*/)[0]
    hash = hash.replace(/\?.*/, '')
  }

  //  Get the path for this use case
  if (hash.includes('/')) path = hash.replace('#', '')

  //  Split the path into its constituent parts
  const pathParts = path.substring(1).split('/')

  //  Redact the path parts as necessary
  const redactionString = ':id'
  const finalParts = pathParts.map(part =>
    isToken(part) ? redactionString : part
  )

  //  Rejoin the path parts and add the query string
  const joinedParts =
    finalParts.length > 1 ? finalParts.join('/') : finalParts.join('')
  const queryString = query ? `?{query}` : ''

  let finalString = `/${joinedParts}${queryString}`

  return finalString
}
