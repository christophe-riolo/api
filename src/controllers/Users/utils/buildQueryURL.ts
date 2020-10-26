import { ObjectAny } from '../../../typings/utils'

export const buildQueryURL = (
  baseURL: string,
  queryObject: ObjectAny
): string => {
  const url = new URL(baseURL)
  for (const query in queryObject) {
    url.searchParams.append(query, queryObject[query])
  }
  return url.href
}
