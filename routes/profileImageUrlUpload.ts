/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      // SSRF mitigation: allow-list hostnames for image fetching
      const allowedHostnames = [
        'images.example.com',
        'cdn.example.net'
        // add more permitted image hostnames as needed
      ]
      let parsedUrl
      try {
        parsedUrl = new URL(url)
      } catch (e) {
        next(new Error('Invalid imageUrl parameter'))
        return
      }
      // SSRF defense: Only allow http/https schemes
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        next(new Error('Unsupported URL protocol'))
        return
      }
      // SSRF defense: Only allow ports 80 (http), 443 (https), or default ('')
      const port = parsedUrl.port || (parsedUrl.protocol === 'http:' ? '80' : (parsedUrl.protocol === 'https:' ? '443' : ''))
      if (port !== '' && port !== '80' && port !== '443') {
        next(new Error('Unsupported port for imageUrl'))
        return
      }
      // SSRF defense: Block any direct IP addresses
      const isIPv4 = /^[0-9\.]+$/.test(parsedUrl.hostname)
      const isIPv6 = /^\[[a-fA-F0-9:]+\]$/.test(parsedUrl.hostname)
      if (isIPv4 || isIPv6) {
        next(new Error('Direct IP addresses are not allowed for imageUrl'))
        return
      }
      if (loggedInUser) {
        if (!allowedHostnames.includes(parsedUrl.hostname)) {
          next(new Error('Unauthorized image hosting provider'))
          return
        }
        try {
          const response = await fetch(parsedUrl.toString())
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
