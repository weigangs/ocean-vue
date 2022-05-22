import { login, logout, getInfo } from '@/api/login'
import { getToken, setToken, removeToken } from '@/utils/auth'
import { encrypt} from '@/utils/jsencrypt'
import Base64 from '@/utils/base64'

const user = {
  state: {
    token: getToken(),
    userId: '',
    name: '',
    avatar: '',
    roles: [],
    permissions: []
  },

  mutations: {
    SET_TOKEN: (state, token) => {
      state.token = token
    },
    SET_USER_ID: (state, userId) => {
      state.userId = userId
    },
    SET_NAME: (state, name) => {
      state.name = name
    },
    SET_AVATAR: (state, avatar) => {
      state.avatar = avatar
    },
    SET_ROLES: (state, roles) => {
      state.roles = roles
    },
    SET_PERMISSIONS: (state, permissions) => {
      state.permissions = permissions
    }
  },

  actions: {
    // 登录
    Login({ commit }, userInfo) {

      // OAUTH2 LOGIN
      var base = new Base64();
      const username = userInfo.username.trim()
      let cryptTxt = encrypt(userInfo.password)
      console.log('rsa=' + cryptTxt)
//解决URL中默认将'+'替换成空字符串问题
      // const password = cryptTxt.replace(new RegExp(/\+/g, "mg"), "2B%")
      const password = encodeURIComponent(cryptTxt)
      const code = userInfo.code
      return new Promise((resolve, reject) => {
        login(username, password, code).then(res => {
          setToken(res.access_token)
          commit('SET_TOKEN', res.access_token)
          resolve()
        }).catch(error => {
          reject(error)
        })
      })
    },

    // 获取用户信息
    GetInfo({ commit, state }) {
      return new Promise((resolve, reject) => {
        getInfo().then(res => {
          const user = res.data
          const avatar = user.avatar == "" ? require("@/assets/images/profile.jpg") : process.env.VUE_APP_BASE_API + user.avatar;
          if (res.roles && res.roles.length > 0) { // 验证返回的roles是否是一个非空数组
            commit('SET_ROLES', user.roles)
            commit('SET_PERMISSIONS', user.permissions)
          } else {
            commit('SET_ROLES', ['ROLE_DEFAULT'])
          }
          commit('SET_USER_ID', user.userId)
          commit('SET_NAME', user.userName)
          commit('SET_AVATAR', avatar)
          resolve(res)
        }).catch(error => {
          reject(error)
        })
      })
    },
    
    // 退出系统
    LogOut({ commit, state }) {
      return new Promise((resolve, reject) => {
        logout(state.token).then(() => {
          commit('SET_TOKEN', '')
          commit('SET_ROLES', [])
          commit('SET_PERMISSIONS', [])
          removeToken()
          resolve()
        }).catch(error => {
          reject(error)
        })
      })
    },

    // 前端 登出
    FedLogOut({ commit }) {
      return new Promise(resolve => {
        commit('SET_TOKEN', '')
        removeToken()
        resolve()
      })
    }
  }
}

export default user
