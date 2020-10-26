import axios from 'axios'
import { Request, Response, Router } from 'express'
import { query } from 'express-validator'
import querystring from 'querystring'

import {
  authenticateUser,
  getUserWithBearerToken
} from '../../../middlewares/authenticateUser'
import { validateRequest } from '../../../middlewares/validateRequest'
import OAuth from '../../../models/OAuth'
import User from '../../../models/User'
import {
  expiresIn,
  generateAccessToken,
  generateRefreshToken
} from '../../../utils/config/jwtToken'
import { ForbiddenError } from '../../../utils/errors/ForbiddenError'
import { isValidRedirectURIValidation } from '../utils/isValidRedirectURIValidation'

const provider = 'discord'

const discordRouter = Router()

discordRouter.get(
  '/add-strategy',
  authenticateUser,
  [
    query('redirectURI')
      .notEmpty()
      .trim()
      .custom(isValidRedirectURIValidation)
  ],
  validateRequest,
  (req: Request, res: Response) => {
    if (req.user == null) {
      throw new ForbiddenError()
    }
    const { redirectURI } = req.query as { redirectURI: string }
    const redirectCallback = `${process.env.API_BASE_URL}/users/oauth2/discord/callback-add-strategy?redirectURI=${redirectURI}`
    const url = `https://discordapp.com/api/v6/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&scope=identify&response_type=code&state=${req.user.accessToken}&redirect_uri=${redirectCallback}`
    return res.json(url)
  }
)

discordRouter.get(
  '/callback-add-strategy',
  [
    query('redirectURI')
      .notEmpty()
      .trim()
      .custom(isValidRedirectURIValidation),
    query('state')
      .notEmpty()
      .trim()
  ],
  validateRequest,
  async (req: Request, res: Response) => {
    const { code, redirectURI, state: accessToken } = req.query as {
      code: string
      redirectURI: string
      state: string
    }
    const userRequest = await getUserWithBearerToken(`Bearer ${accessToken}`)
    const { data: dataTokens } = await axios.post<{
      access_token: string
      token_type: string
      expires_in: number
      refresh_token: string
      scope: 'identify'
    }>(
      'https://discordapp.com/api/v6/oauth2/token',
      querystring.stringify({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${process.env.API_BASE_URL}/users/oauth2/discord/callback-add-strategy?redirectURI=${redirectURI}`,
        scope: 'identify'
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    )

    const { data: dataUser } = await axios.get<{
      id: string
      username: string
      discriminator: string
    }>('https://discordapp.com/api/v6/users/@me', {
      headers: {
        Authorization: `${dataTokens.token_type} ${dataTokens.access_token}`
      }
    })

    let message = 'success'
    const OAuthUser = await OAuth.findOne({
      where: { providerId: dataUser.id, provider }
    })

    if (OAuthUser != null) {
      if (OAuthUser.userId !== userRequest.current.id) {
        message = 'This account is already used by someone else'
      } else {
        message = 'You are already using this account'
      }
    } else {
      await OAuth.create({
        provider,
        providerId: dataUser.id,
        userId: userRequest.current.id
      })
    }

    const url = new URL(redirectURI)
    url.searchParams.append('message', message)
    return res.redirect(url.href)
  }
)

discordRouter.get(
  '/signin',
  [
    query('redirectURI')
      .notEmpty()
      .trim()
      .custom(isValidRedirectURIValidation)
  ],
  validateRequest,
  (req: Request, res: Response) => {
    const { redirectURI } = req.query as { redirectURI: string }
    const redirectCallback = `${process.env.API_BASE_URL}/users/oauth2/discord/callback?redirectURI=${redirectURI}`
    const url = `https://discordapp.com/api/v6/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&scope=identify&response_type=code&redirect_uri=${redirectCallback}`
    return res.json(url)
  }
)

discordRouter.get(
  '/callback',
  [
    query('code').notEmpty(),
    query('redirectURI')
      .notEmpty()
      .trim()
      .custom(isValidRedirectURIValidation)
  ],
  validateRequest,
  async (req: Request, res: Response) => {
    const { code, redirectURI } = req.query as {
      code: string
      redirectURI: string
    }
    const { data: dataTokens } = await axios.post<{
      access_token: string
      token_type: string
      expires_in: number
      refresh_token: string
      scope: 'identify'
    }>(
      'https://discordapp.com/api/v6/oauth2/token',
      querystring.stringify({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${process.env.API_BASE_URL}/users/oauth2/discord/callback?redirectURI=${redirectURI}`,
        scope: 'identify'
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    )

    const { data: dataUser } = await axios.get<{
      id: string
      username: string
      discriminator: string
    }>('https://discordapp.com/api/v6/users/@me', {
      headers: {
        Authorization: `${dataTokens.token_type} ${dataTokens.access_token}`
      }
    })

    const OAuthUser = await OAuth.findOne({
      where: { providerId: dataUser.id, provider }
    })
    let userId: number = OAuthUser?.user?.id

    if (OAuthUser == null) {
      let name = dataUser.username
      let isAlreadyUsedName = true
      let countId: string | number = dataUser.discriminator
      while (isAlreadyUsedName) {
        const foundUsername = await User.findOne({ where: { name } })
        isAlreadyUsedName = foundUsername != null
        if (isAlreadyUsedName) {
          name = `${name}-${countId}`
          countId = Math.random() * Date.now()
        }
      }
      const user = await User.create({ name })
      userId = user.id
      await OAuth.create({
        provider,
        providerId: dataUser.id,
        userId: user.id
      })
    }

    const accessToken = generateAccessToken({
      id: userId,
      strategy: provider
    })
    const refreshToken = await generateRefreshToken({
      strategy: provider,
      id: userId
    })

    const url = new URL(redirectURI)
    url.searchParams.append('accessToken', accessToken)
    url.searchParams.append('refreshToken', refreshToken)
    url.searchParams.append('expiresIn', expiresIn.toString())
    url.searchParams.append('type', 'Bearer')
    return res.redirect(url.href)
  }
)

export { discordRouter }
