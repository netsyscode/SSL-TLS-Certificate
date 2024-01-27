
import request from '@/utils/request'

export function listScanProcess(query) {
  return request({
    url: '/system/scan-process/list',
    method: 'get',
    params: query
  })
}


export function addScanProcess(data) {
  return request({
    url: '/system/scan-process',
    method: 'post',
    data: data
  })
}
