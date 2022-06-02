
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJfw16ihbjEiPcMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi14YXQ2dnNxaC51cy5hdXRoMC5jb20wHhcNMjEwNjI4MDY0NDA0WhcN
MzUwMzA3MDY0NDA0WjAkMSIwIAYDVQQDExlkZXYteGF0NnZzcWgudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAztN75jeSq+MJo6Kq
1mLah1XRQSxoN+2Oq12VdSk8YnOk61fCdxmomLFN/Icdiriahi0qK/wyLt6pT+1v
QxGnCCfKr2HZKqUxOISiZs/OdEfG7CR7geCjapRyQZmo16HyXC8+39HInmvczTQN
hCJ6eXhZ7NC5HORP4ERATC7fNua/dT0Nm9lniBzSWZHK9pmA83YXmQjZIhEkm3XC
eq2pWFuwdalpS+P4vX/8reri5aIQ2NLZBF6UZI8GZ03G6zPCzv1DoruFSdGtWjcl
H2KEvnfjQF9VioViuuUYAjkjkutKUAdGnAEtGHImghmQXcxoWYsbAC1Q8tCDxHJO
QtCG/QIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQNd7LXbhp+
jAwil2chqjgnI/BTJTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
ADjgmdofTUiFMgClwT0VHNyUWABMsDYQamgImnDblICSShbDHyY8boe6T02uC+o5
7FgldEDRK3aXT3myzO0F2ASOFk6gzQSt8aCiyYSs456gxzMc4vPOzT0oVIJtxcEe
00lgrbtLOZ3b/22dhlW//5w04KdkYBHkueYcGiD+GPZIHxwr3I+7mEYWXGWS6nT3
BJ1HWVMVdzbnk9Ke0OR3eJV7EEH6bVRhYloKRKLJ6xO4IxEEdqkznxhTLoGhrxRb
iRcGGHqQpe17x3OlP2FFgaXMgRyVE0baoaWGhT9h+excCeRZpPEe/n7BalKBkriK
qkY+ZoDGmDBHJFxKtvpJqqE=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
