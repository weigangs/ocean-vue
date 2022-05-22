import request from '@/utils/request'
import store from '../store'

// 获取路由
export const getRouters = () => {
  return request({
    url: '/sysLogin/getMenus/' + store.getters.userId,
    method: 'get'
  })
}