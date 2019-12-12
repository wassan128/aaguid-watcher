import { isWebAuthnSupported } from './utils.js'
import { Base64 } from './lib/base64.js'

const getAttestationOptions = () => {
    const name = document.getElementById('username').value
    const challenge = crypto.getRandomValues(new Uint8Array(32))
    const user_id = crypto.getRandomValues(new Uint8Array(32))

    const credentialCreationOptions = {
        'challenge': challenge,
        'rp': {
            'name': 'webauthn demo'
        },
        'user': {
            'id': user_id,
            'name': name,
            'displayName': name
        },
        'pubKeyCredParams': [
            { 'type': 'public-key', 'alg': -7 }
        ],
        'timeout': 60000,
        'authenticatorSelection': {
            'userVerification': 'discouraged'
        },
        'attestation': 'direct'

    }

    return credentialCreationOptions
}

const Register = async () =>  {
    const publicKey = getAttestationOptions()

    const credential = await navigator.credentials.create({ publicKey: publicKey })
    const {id, rawId, response, type} = credential
    const {attestationObject, clientDataJSON} = response

    const clientData = JSON.parse(
        String.fromCharCode(...new Uint8Array(clientDataJSON))
    )

    const clientDataHash = sha256(clientDataJSON)
    const {fmt, authData, attStmt} = CBOR.decode(attestationObject)
    const rpIdHash = authData.slice(0, 32).reduce((res, x) => res+`0${x.toString(16)}`.slice(-2), '')
    if (rpIdHash !== sha256('webauthn-demo-app')) {
        console.error('Incorrect RP id hash not equal sha256(webauthn-demo-app)')
    }

    const flag = authData[32]
    const [ed, at, uv, up] = [
        (flag & 0x80) >> 7,
        (flag & 0x40) >> 6,
        (flag & 0x04) >> 2,
        flag & 0x01
    ]
    if (uv !== 1) {
        console.warn('UserVerified is not 1')
    }
    if (up !== 1) {
        console.warn('UserPresent is not 1')
    }

    const counter = authData.slice(33, 37)
    const aaguid = authData.slice(37, 53)

    const credentialIdLength = (authData[53] << 8) + authData[54]
    const credentialId = Base64.encode(authData.slice(55, 55 + credentialIdLength))

    const publicKeyBytes = authData.slice(55 + credentialIdLength)
    const publicKeyObj = CBOR.decode(publicKeyBytes.buffer)

    const parsedAttesatationObject = {
        id,
        rawId: Base64.encode(rawId),
        response: {
            attestationObject: {
                attStmt: {
                    sig: attStmt.sig ? Base64.encode(attStmt.sig) : '',
                    x5c: attStmt.x5c ? Base64.encode(attStmt.x5c[0]) : [],
                },
                authData: {
                    rpIdHash: Base64.encode(rpIdHash),
                    flag: {
                        UP: up,
                        UV: uv,
                        AT: at,
                        ED: ed,
                    },
                    counter: counter[0] + (counter[1] << 1) + (counter[2] << 2) + (counter[3] << 3),
                    aaguid: Base64.encode(aaguid),
                    credentialId: credentialId
                },
                fmt
            },
            clientDataJSON: clientDataJSON
        }
    }
    console.log('attestation Object: ', parsedAttesatationObject)

    document.getElementById('aaguid').value = aaguid
    document.getElementById('aaguid-b64').value = Base64.encode(aaguid)
    document.getElementById('aaguid-chr').value = aaguid.reduce((res, x) => res += String.fromCharCode(x), "")
}

const sha256 = (target) => {
    const SHA_OBJ = new jsSHA('SHA-256', 'TEXT')
    SHA_OBJ.update(target)
    return SHA_OBJ.getHash('HEX')
}

document.addEventListener('DOMContentLoaded', () => {
    const btn_register = document.getElementById('btn-register')
    btn_register.addEventListener('click', Register)
})
