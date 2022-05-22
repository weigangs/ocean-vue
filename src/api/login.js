import request from '@/utils/request'
import user from '../store/modules/user'

// 登录方法
export function login(username, password, code) {
  const data = {
    username,
    password,
    code
  }

  data.client_id = 'frontend'
  data.client_secret = 'frontend'
  data.grant_type = 'password'

  let url = '/oauth/token?username=' + username + '&password=' +password+ '&code=' +code+ '&client_id=' +data.client_id+ '&client_secret=' +data.client_secret+ '&grant_type=' + data.grant_type
  console.log(url)
  return request({
    url: url,
    method: 'post',
    data: data
  })
}

// 注册方法
export function register(data) {
  return request({
    url: '/register',
    headers: {
      isToken: false
    },
    method: 'post',
    data: data
  })
}

// 获取用户详细信息
export function getInfo() {
  return request({
    url: '/sysLogin/user',
    method: 'get'
  })
}

// 退出方法
export function logout() {
  return request({
    url: '/logout',
    method: 'post'
  })
}

// 获取验证码
export function getCodeImg() {
  return request({
    url: '/verify/code',
    method: 'get'
  })
}