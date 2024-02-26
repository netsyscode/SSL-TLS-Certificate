
import request from '@/utils/request'

export function listCert(query) {
  return request({
    url: '/system/cert_search/list',
    method: 'get',
    params: query
  })
}


export function getCertInfo(certId) {
  return request({
    url: '/system/cert_retrive/' + certId,
    method: 'get'
  })
}
