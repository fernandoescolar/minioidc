// Passkeys (WebAuthn) of the login and the passkeys pages. The pages work
// without this script: its controls are hidden until the browser supports
// passkeys. The server sends the WebAuthn options as JSON (the binary values
// base64url encoded) and receives the credentials in the same format.
(function () {
  'use strict'

  const supported = !!(window.PublicKeyCredential && navigator.credentials)

  function toBuffer(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer
  }

  function toBase64URL(buffer) {
    let binary = ''
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  const descriptors = (list) => (list || []).map((c) => ({ ...c, id: toBuffer(c.id) }))

  async function post(url, body) {
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Minioidc-Passkey': '1' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })

    let data = {}
    try {
      data = await response.json()
    } catch {
      // not a JSON answer
    }

    if (!response.ok) throw new Error(data.error || 'The passkey request failed. Try it again.')
    return data
  }

  // the user closed the dialog of the browser, or another request replaced it
  const cancelled = (error) => error && (error.name === 'NotAllowedError' || error.name === 'AbortError')

  function message(error) {
    if (error && error.name === 'InvalidStateError') return 'This device already has a passkey for your account.'
    if (error && error.name === 'SecurityError') return 'Passkeys need a secure (https) connection to this site.'
    return (error && error.message) || 'The passkey could not be used. Try it again.'
  }

  function show(element, text) {
    if (!element) return
    element.textContent = text || ''
    element.hidden = !text
  }

  // the login: a button, and the passkeys suggested by the username field
  const login = document.querySelector('[data-passkey-login]')
  if (login && supported) {
    const button = login.querySelector('button')
    const error = login.querySelector('[data-passkey-error]')
    let autofill = null

    const signIn = async (conditional) => {
      const options = await post(login.dataset.begin)
      const publicKey = { ...options.publicKey, challenge: toBuffer(options.publicKey.challenge), allowCredentials: descriptors(options.publicKey.allowCredentials) }
      const request = { publicKey }
      if (conditional) {
        autofill = new AbortController()
        request.mediation = 'conditional'
        request.signal = autofill.signal
      }

      const credential = await navigator.credentials.get(request)
      const result = await post(login.dataset.finish + window.location.search, {
        id: credential.id,
        rawId: toBase64URL(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toBase64URL(credential.response.clientDataJSON),
          authenticatorData: toBase64URL(credential.response.authenticatorData),
          signature: toBase64URL(credential.response.signature),
          userHandle: credential.response.userHandle ? toBase64URL(credential.response.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      })
      window.location.assign(result.redirect)
    }

    login.hidden = false
    button.addEventListener('click', async () => {
      // the browser only allows one request: the button replaces the autofill
      if (autofill) autofill.abort()
      show(error)
      button.disabled = true
      try {
        await signIn(false)
      } catch (e) {
        if (!cancelled(e)) show(error, message(e))
      } finally {
        button.disabled = false
      }
    })

    if (PublicKeyCredential.isConditionalMediationAvailable) {
      PublicKeyCredential.isConditionalMediationAvailable().then((available) => {
        if (available) signIn(true).catch((e) => cancelled(e) || show(error, message(e)))
      })
    }
  }

  // the passkeys page: add a passkey
  const register = document.querySelector('[data-passkey-register]')
  if (register) {
    if (!supported) {
      const unsupported = document.querySelector('[data-passkey-unsupported]')
      if (unsupported) unsupported.hidden = false
    } else {
      const button = register.querySelector('button[type="submit"]')
      const error = register.querySelector('[data-passkey-error]')
      register.hidden = false
      register.addEventListener('submit', async (event) => {
        event.preventDefault()
        show(error)
        button.disabled = true
        try {
          const options = await post(register.dataset.begin)
          const publicKey = {
            ...options.publicKey,
            challenge: toBuffer(options.publicKey.challenge),
            user: { ...options.publicKey.user, id: toBuffer(options.publicKey.user.id) },
            excludeCredentials: descriptors(options.publicKey.excludeCredentials),
          }

          const credential = await navigator.credentials.create({ publicKey })
          const name = register.elements.name.value
          const result = await post(register.dataset.finish + '?name=' + encodeURIComponent(name), {
            id: credential.id,
            rawId: toBase64URL(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: toBase64URL(credential.response.clientDataJSON),
              attestationObject: toBase64URL(credential.response.attestationObject),
              transports: credential.response.getTransports ? credential.response.getTransports() : [],
            },
            clientExtensionResults: credential.getClientExtensionResults(),
          })
          window.location.assign(result.redirect)
        } catch (e) {
          if (!cancelled(e)) show(error, message(e))
        } finally {
          button.disabled = false
        }
      })
    }
  }
})()
