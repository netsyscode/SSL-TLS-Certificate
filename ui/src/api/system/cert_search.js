
import request from '@/utils/request'

export function listScanProcess(query) {
  return request({
    url: '/system/cert_search/list',
    method: 'get',
    params: query
  })
}


export function addScanProcess(data) {
  return request({
    url: '/system/cert_search',
    method: 'post',
    data: data
  })
}
