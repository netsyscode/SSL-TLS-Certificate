import Vue from 'vue'

import Cookies from 'js-cookie'

import * as d3 from 'd3';
/**
 * 
 * Could not find a declaration file for module 'd3'. 'e:/global_ca_monitor/ui/node_modules/d3/src/index.js' implicitly has an 'any' type.
  Try `npm i --save-dev @types/d3` if it exists or add a new declaration (.d.ts) file containing `declare module 'd3';`ts(7016)
  
 * d3 has no 这是因为有些第三方库已经为 TypeScript 提供了官方的类型声明文件，并且这些文件与库本身捆绑在一起。这种情况下，你不需要额外安装 @types/ 包来获取类型声明，因为它们已经包含在库本身中。
  对于 Element UI 这样的库，它提供了官方的 TypeScript 类型定义文件，位于 node_modules/element-ui/types/ 目录下。这些类型声明文件告诉 TypeScript 如何正确地使用 Element UI 组件，因此你可以在 TypeScript 项目中使用 Element UI 而无需执行额外的类型安装命令。
  所以，当你安装 Element UI 时，不需要额外安装 @types/element-ui 或其他类型声明包，因为 Element UI 库本身就已经包含了 TypeScript 类型声明文件。
 * 
 */

import Element from 'element-ui'
import './assets/styles/element-variables.scss'

import '@/assets/styles/index.scss' // global css
import '@/assets/styles/ruoyi.scss' // ruoyi css
import App from './App'
import store from './store'
import router from './router'
import directive from './directive' // directive
import plugins from './plugins' // plugins
import { download } from '@/utils/request'

import './assets/icons' // icon
import './permission' // permission control
import { getDicts } from "@/api/system/dict/data";
import { getConfigKey } from "@/api/system/config";
import { parseTime, resetForm, addDateRange, selectDictLabel, selectDictLabels, handleTree } from "@/utils/ruoyi";
// 分页组件
import Pagination from "@/components/Pagination";
// 自定义表格工具组件
import RightToolbar from "@/components/RightToolbar"
// 富文本组件
import Editor from "@/components/Editor"
// 文件上传组件
import FileUpload from "@/components/FileUpload"
// 图片上传组件
import ImageUpload from "@/components/ImageUpload"
// 图片预览组件
import ImagePreview from "@/components/ImagePreview"
// 字典标签组件
import DictTag from '@/components/DictTag'
// 头部标签组件
import VueMeta from 'vue-meta'
// 字典数据组件
import DictData from '@/components/DictData'

// 全局方法挂载
Vue.prototype.getDicts = getDicts
Vue.prototype.getConfigKey = getConfigKey
Vue.prototype.parseTime = parseTime
Vue.prototype.resetForm = resetForm
Vue.prototype.addDateRange = addDateRange
Vue.prototype.selectDictLabel = selectDictLabel
Vue.prototype.selectDictLabels = selectDictLabels
Vue.prototype.download = download
Vue.prototype.handleTree = handleTree

// 全局组件挂载
Vue.component('DictTag', DictTag)
Vue.component('Pagination', Pagination)
Vue.component('RightToolbar', RightToolbar)
Vue.component('Editor', Editor)
Vue.component('FileUpload', FileUpload)
Vue.component('ImageUpload', ImageUpload)
Vue.component('ImagePreview', ImagePreview)

Vue.use(directive)
Vue.use(plugins)
Vue.use(VueMeta)
DictData.install()

/**
 * If you don't want to use mock-server
 * you want to use MockJs for mock api
 * you can execute: mockXHR()
 *
 * Currently MockJs will be used in the production environment,
 * please remove it before going online! ! !
 */

Vue.use(Element, {
  size: Cookies.get('size') || 'medium' // set element-ui default size
})

Vue.config.productionTip = false

new Vue({
  el: '#app',
  router,
  store,
  render: h => h(App)
})
