import { Server as HttpServer } from 'http'
import { Server as HttpsServer } from 'https'
import socketIo, { Server as SocketIoServer } from 'socket.io'

import Member from '../../models/Member'

interface Socket {
  io: null | SocketIoServer
  init: (httpServer: HttpServer | HttpsServer) => void
}

export const socket: Socket = {
  io: null,
  init (httpServer) {
    socket.io = socketIo(httpServer)
  }
}

interface EmitEventOptions {
  event: string
  payload: {
    action: 'create' | 'delete' | 'update'
    [key: string]: any
  }
}

interface EmitToMembersOptions extends EmitEventOptions {
  guildId: number
}

interface EmitToAuthorizedUsersOptions extends EmitEventOptions {
  /** tests whether the current connected userId is authorized to get the event, if the callback returns true, the server will emit the event to that user */
  isAuthorizedCallback: (userId: number) => boolean | Promise<boolean>
}

/** emits socket.io event to every connected authorized users */
export const emitToAuthorizedUsers = (
  options: EmitToAuthorizedUsersOptions
): void => {
  const { event, payload, isAuthorizedCallback: callback } = options
  socket.io?.sockets.clients(async (_error: Error, clients: string[]) => {
    for (const clientId of clients) {
      const client = socket.io?.sockets.connected[clientId]
      const userId: number = (client as any).decoded_token?.id
      const isAuthorized = await callback(userId)
      if (isAuthorized) {
        client?.emit(event, payload)
      }
    }
  })
}

/** emits socket.io event to every connected members of the guild */
export const emitToMembers = (options: EmitToMembersOptions): void => {
  emitToAuthorizedUsers({
    event: options.event,
    payload: options.payload,
    isAuthorizedCallback: async userId => {
      const member = await Member.findOne({
        where: { userId, guildId: options.guildId }
      })
      return member != null
    }
  })
}
