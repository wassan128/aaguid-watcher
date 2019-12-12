'use strict'

export const isWebAuthnSupported = () => {
    return !(window.PublicKeyCredential === undefined &&
        typeof window.PublicKeyCredential !== 'function')
}
